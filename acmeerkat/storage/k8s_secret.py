import base64
import gzip
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from ssl import SSLContext, PROTOCOL_TLS_CLIENT
from typing import Any, ClassVar, Literal, Self
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from acmeerkat import BaseKVStorage


__all__ = (
    'K8sApi',
    'K8sApiError',
    'K8sSecretStorage',
    'Kind',
)


class K8sApiError(Exception):
    pass


class Kind(Enum):
    Secret = 'secrets'


@dataclass
class K8sApi:
    base_api_url: str
    namespace: str
    token: str
    ssl_context: SSLContext
    timeout: float | int = 15

    @classmethod
    def create_from_pod(cls) -> Self:
        d = Path('/var/run/secrets/kubernetes.io/serviceaccount/')
        ssl_context = SSLContext(PROTOCOL_TLS_CLIENT)
        ssl_context.load_verify_locations(cafile=str(d / 'ca.crt'))
        return cls(
            'https://{}:{}'.format(
                os.environ['KUBERNETES_SERVICE_HOST'],
                os.environ['KUBERNETES_SERVICE_PORT_HTTPS']),
            (d / 'namespace').read_text(),
            (d / 'token').read_text(),
            ssl_context)

    def _get_objects_url(
        self, kind: Kind, namespace: str | None = None,
    ) -> str:
        n = self.namespace if namespace is None else namespace
        return f'{self.base_api_url}/api/v1/namespaces/{n}/{kind.value}'

    def _request(
        self,
        method: Literal['GET', 'POST', 'HEAD', 'DELETE', 'PUT'],
        url: str,
        send_json: dict[Any, Any] | None = None,
        allow_404: bool = False,
    ) -> tuple[int, dict[Any, Any] | None]:
        hdrs = {'Authorization': f'Bearer {self.token}'}
        if send_json is not None:
            hdrs['Content-Type'] = 'application/json'
        req = Request(
            url,
            method=method,
            headers=hdrs,
            data=(
                None if send_json is None else
                json.dumps(send_json).encode('utf-8')))
        try:
            resp = urlopen(req, timeout=self.timeout, context=self.ssl_context)
        except HTTPError as e:
            resp = e
        raw_body = None if method == 'HEAD' else resp.read()
        resp_json = None if not raw_body else json.loads(
            raw_body.decode('utf-8'))
        if (200 <= resp.status < 300) or (resp.status == 404 and allow_404):
            return resp.status, resp_json
        raise K8sApiError(f'HTTP {resp.status} {resp_json!r}')

    def upsert_object(
        self,
        kind: Kind,
        name: str,
        chart: dict[Any, Any],
        recreate: bool = False,
        namespace: str | None = None,
    ) -> dict[Any, Any]:
        objects_url = self._get_objects_url(kind, namespace)
        object1_url = f'{objects_url}/{name}'
        if recreate:
            self._request('DELETE', object1_url, allow_404=True)
        else:
            status, resp = self._request(
                'PUT', object1_url, chart, allow_404=True)
            if status < 400:  # succeeds only if object exists
                if resp is None:
                    raise ValueError
                return resp
        _, resp = self._request('POST', objects_url, chart)
        if resp is None:
            raise ValueError
        return resp

    def get_object(
        self,
        kind: Kind,
        name: str,
        namespace: str | None = None,
    ) -> dict[Any, Any] | None:
        objects_url = self._get_objects_url(kind, namespace)
        object1_url = f'{objects_url}/{name}'
        status, resp = self._request('GET', object1_url, allow_404=True)
        if status == 404:
            return None
        return resp


@dataclass
class KvBufReader:
    buf: bytes
    offset: int = 0

    def read_uint32(self) -> int:
        s = self.buf[self.offset:self.offset + 4]
        if len(s) != 4:
            raise ValueError('Incomplete int32 value')
        self.offset += 4
        return int.from_bytes(s)

    def read_chunk(self, size: int) -> bytes:
        s = self.buf[self.offset:self.offset + size]
        if len(s) != size:
            raise ValueError(f'Incomplete {size} chunk, got {len(s)}')
        self.offset += size
        return s

    def read_kv(self) -> dict[bytes, bytes]:
        r = {}
        count = self.read_uint32()
        for _ in range(count):
            klen = self.read_uint32()
            k = self.read_chunk(klen)
            vlen = self.read_uint32()
            v = self.read_chunk(vlen)
            r[k] = v
        return r


def _uint32_to_bytes(value: int) -> bytes:
    return value.to_bytes(4)


def serialize(data: dict[bytes, bytes]) -> bytes:
    parts = [_uint32_to_bytes(len(data))]
    for key, value in data.items():
        parts.append(_uint32_to_bytes(len(key)))
        parts.append(key)
        parts.append(_uint32_to_bytes(len(value)))
        parts.append(value)
    return b''.join(parts)


@dataclass
class K8sSecretStorage(BaseKVStorage):
    k8s_api: K8sApi
    secret_name: str

    _data: dict[bytes, bytes] = field(init=False)

    _FNAME: ClassVar[str] = 'kv.v1.gz'
    _OBJTYPE: ClassVar[str] = 'acmeerkat-key-value'

    def __post_init__(self) -> None:
        self._data = self._load_data()

    def _load_data(self) -> dict[bytes, bytes]:
        o = self.k8s_api.get_object(Kind.Secret, self.secret_name)
        if o is None:
            return {}
        if o.get('kind') != 'Secret':
            raise ValueError('Object muse be a Secret')
        if not isinstance(o.get('data'), dict):
            raise ValueError('Secret must contain data')
        if not isinstance(o['data'].get(self._FNAME), str):
            raise ValueError(f'Secret data must have file {self._FNAME}')
        return KvBufReader(gzip.decompress(
            base64.b64decode(o['data'][self._FNAME].encode('ascii'))
        )).read_kv()

    def update(self, u: dict[bytes, bytes]) -> None:
        for k, v in u.items():
            if not v:
                self._data.pop(k, None)
            else:
                self._data[k] = v
        self.k8s_api.upsert_object(Kind.Secret, self.secret_name, {
            'apiVersion': 'v1',
            'kind': 'Secret',
            'metadata': {'name': self.secret_name},
            'immutable': False,  # to be able to patch using single request
            'type': self._OBJTYPE,
            'data': {
                self._FNAME: base64.b64encode(gzip.compress(
                    serialize(self._data),
                    compresslevel=9)).decode('ascii'),
            },
        })

    def get(self, k: bytes) -> bytes:
        return self._data.get(k, b'')
