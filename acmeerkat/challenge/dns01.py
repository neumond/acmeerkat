import hashlib
import json
from collections import abc
from contextlib import contextmanager
from dataclasses import dataclass, field
from time import sleep
from typing import Any, ClassVar, Literal

from acmeerkat import (
    AuthzIdentifier, b64_jose, BaseChallenge, BaseHttpsClient, ChallengeConfig)


__all__ = (
    'BaseDns01',
    'CloudflareDns01',
    'CloudflareDnsError',
    'ManualDns01',
)


class BaseDns01(BaseChallenge):
    TYPE: ClassVar[str] = 'dns-01'
    RECORD_NAME: ClassVar[str] = '_acme-challenge'

    def rec_create(self, content: str) -> None:
        raise NotImplementedError

    def rec_remove(self) -> None:
        raise NotImplementedError

    @contextmanager
    def _perform(
        self,
        identifier: AuthzIdentifier,
        config: ChallengeConfig,
        thumbprint: str,
    ) -> abc.Iterator[None]:
        ka = f'{config["token"]}.{thumbprint}'.encode('utf-8')
        try:
            self.rec_create(b64_jose(hashlib.sha256(ka).digest()))
            yield
        finally:
            self.rec_remove()


class ManualDns01(BaseDns01):
    def rec_create(self, content: str) -> None:
        print('Create TXT record:')
        print(f'       Name: {self.RECORD_NAME}')
        print(f'    Content: "{content}"')
        print('Press enter when ready')
        input()

    def rec_remove(self) -> None:
        print(f'Remove TXT record {self.RECORD_NAME}')
        print('Press enter when ready')
        input()


class CloudflareDnsError(Exception):
    pass


def _format_cf_error(err: dict[str, Any]) -> str:
    parts = []
    for k in ['code', 'message', 'documentation_url']:
        if (p := err.get(k)) is not None:
            parts.append(str(p))
    return ' '.join(parts)


@dataclass(kw_only=True)
class CloudflareDns01(BaseDns01):
    https_client: BaseHttpsClient
    account: str
    token: str
    zone: str
    record_ttl: int = 60
    sleep: float = 10.  # wait some time before starting acme check

    _record: str | None = field(init=False, default=None)

    def _request(
        self,
        method: Literal['GET', 'POST', 'HEAD', 'DELETE'],
        relurl: str,
        body: bytes | None,
    ) -> Any:
        status, body, _ = self.https_client.request(
            method=method,
            url=f'https://api.cloudflare.com/client/v4{relurl}',
            send_body=body,
            send_headers={'Authorization': f'Bearer {self.token}'},
            return_headers=())
        if body is None:
            raise CloudflareDnsError('Expected response body')
        resp = json.loads(body.decode('utf-8'))
        if not resp.get('success'):
            raise CloudflareDnsError('\n'.join(
                _format_cf_error(e) for e in resp.get('errors', ())))
        if not (200 <= status < 300):
            raise CloudflareDnsError(f'Bad HTTP status: {status}')
        return resp.get('result')

    def rec_create(self, content: str) -> None:
        txt_record = {
            'type': 'TXT',
            'name': self.RECORD_NAME,
            'ttl': self.record_ttl,
            'content': content}
        resp = self._request(
            method='POST',
            relurl=f'/zones/{self.zone}/dns_records',
            body=json.dumps(txt_record).encode('utf-8'))
        self._record = resp.get('id')
        sleep(self.sleep)

    def rec_remove(self) -> None:
        if self._record is None:
            return
        self._request(
            method='DELETE',
            relurl=f'/zones/{self.zone}/dns_records/{self._record}',
            body=None)
