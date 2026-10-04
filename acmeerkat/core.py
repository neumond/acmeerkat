import base64
import contextlib
import hashlib
import json
from collections import abc
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
from random import random
from time import sleep
from typing import (
    cast, ClassVar, get_args, Literal, Required, Self, TypedDict, TypeGuard)

from .error import AcmeError
from . import error


__all__ = (
    'BaseKVStorage', 'BaseHTTPSClient', 'BaseCrypto',
    'KVNamespace', 'Algorithm', 'KeyPairBytes',
    'KeyType', 'is_valid_key_type',
    'CurveType', 'is_valid_curve_type',
    'PublicKeyDict',
    'b64_jose', 'JSONWebSignature', 'AcmeError',
    'BaseChallenge', 'BaseTokenChallenge',
    'ProviderAccount', 'CertUpdater',
)


USER_AGENT = 'Acmeerkat/0.1'
COMPACT_JSON_SEP = (',', ':')


def b64_jose(b):
    return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')


def bin_json_dumps(d: dict, separators=COMPACT_JSON_SEP) -> bytes:
    return json.dumps(d, separators=separators).encode('utf-8')


def jws_serialize(d: dict, separators=COMPACT_JSON_SEP) -> str:
    return b64_jose(bin_json_dumps(d, separators=separators))


class BaseKVStorage:
    def update(self, u: dict[bytes, bytes]) -> None:
        "Assigning empty value b'' deletes the key"
        raise NotImplementedError

    def get(self, k: bytes) -> bytes:
        "Non-existent key yields b''"
        raise NotImplementedError


@dataclass
class KVNamespace:
    storage: BaseKVStorage
    prefix: bytes = b''

    def update(self, u: dict[bytes, bytes]) -> None:
        return self.storage.update({
            self.prefix + k: v
            for k, v in u.items()})

    def get(self, k: bytes) -> bytes:
        return self.storage.get(self.prefix + k)

    def descend(self, prefix: bytes) -> Self:
        return type(self)(self.storage, self.prefix + prefix)


class Algorithm(Enum):
    # rfc7518
    ES256 = 'ES256'  # ECDSA using P-256 and SHA-256


KeyType = Literal['EC', 'RSA']


def is_valid_key_type(kty: str) -> TypeGuard[KeyType]:
    return kty in get_args(KeyType)


CurveType = Literal['P-256']


def is_valid_curve_type(crv: str) -> TypeGuard[CurveType]:
    return crv in get_args(CurveType)


PublicKeyDict = TypedDict('PublicKeyDict', {
    # rfc7517, JSON Web Key
    'kty': Required[KeyType],
    'crv': CurveType,
    'x': str,
    'y': str,
    'e': str,
    'n': str,
}, total=False)


_JWK_THUMBPRINT_REQ_KEYS = {
    'EC': frozenset(['crv', 'kty', 'x', 'y']),
    'RSA': frozenset(['e', 'kty', 'n']),
}


def jwk_thumbprint(d: PublicKeyDict) -> str:
    # JSON Web Key (JWK) Thumbprint, rfc7638
    req_fs = _JWK_THUMBPRINT_REQ_KEYS[d['kty']]
    return b64_jose(hashlib.sha256(json.dumps(
        {k: v for k, v in d.items() if k in req_fs},
        separators=(',', ':'),
        sort_keys=True,
    ).encode('utf-8')).digest())


# should be openssl compatible
type KeyPairBytes = bytes

# rfc7518
type JSONWebSignature = str


@dataclass
class BaseCrypto:
    def generate_key_pair(self, a: Algorithm) -> KeyPairBytes:
        raise NotImplementedError

    def check_key_pair(self, key_pair: KeyPairBytes) -> bool:
        raise NotImplementedError

    def pubkey_params(self, key_pair: KeyPairBytes) -> PublicKeyDict:
        raise NotImplementedError

    def sign(self, key_pair: KeyPairBytes, data: bytes) -> JSONWebSignature:
        raise NotImplementedError

    def generate_csr(
        self, key_pair: KeyPairBytes, domains: list[str],
    ) -> bytes:
        raise NotImplementedError


AccountDict = TypedDict('AccountDict', {
    '__Location': Required[str | None],
    'status': Required[str],  # valid | deactivated | revoked
    'contact': list[str],
    'termsOfServiceAgreed': bool,
    # orders: str
    # TODO: externalAccountBinding: dict
    # createdAt: str
    # key: dict
}, total=False)


@dataclass
class BaseHTTPSClient:
    directory_url: str
    user_agent: str = USER_AGENT
    accept_language: str = 'en, *;q=0.5'  # localized error messages

    _nonce: str | None = field(init=False, default=None)

    JSON_MIME: ClassVar[str] = 'application/json'
    PROBLEM_JSON_MIME: ClassVar[str] = 'application/problem+json'
    JOSE_JSON_MIME: ClassVar[str] = 'application/jose+json'
    PEM_CHAIN_MIME: ClassVar[str] = 'application/pem-certificate-chain'
    NONCE_HEADER: ClassVar[str] = 'Replay-Nonce'
    CTYPE_HEADER: ClassVar[str] = 'Content-Type'
    ACCEPT_HEADER: ClassVar[str] = 'Accept'

    def request(
        self,
        method: Literal['GET', 'POST', 'HEAD'],
        url: str,
        send_body: bytes | None,
        send_headers: dict[str, str],
        return_headers: abc.Iterable[str],
    ) -> tuple[int, bytes | None, dict[str, str]]:
        """
        Returns (status, body, returned_headers)
        Keys in result of return_headers must have the same case
        If resp header doesn't exist, omit the entry in result
        """
        raise NotImplementedError

    def _def_hdrs(self) -> dict[str, str]:
        return {
            'User-Agent': self.user_agent,
            'Accept-Language': self.accept_language,
        }

    def _resp(
        self,
        r: tuple[int, bytes | None, dict[str, str]],
        capture_headers: abc.Iterable[str] = (),
    ) -> dict | bytes:
        status, data, hdrs = r
        bad_status = not (200 <= status < 300)
        if data is None:
            data = b''

        ct = hdrs.get(self.CTYPE_HEADER, '')
        if ';' in ct:
            ct, _ = ct.split(';', 1)
            # TODO: handle charset=utf-8
        match ct.strip():
            case self.JSON_MIME | self.JOSE_JSON_MIME | self.PROBLEM_JSON_MIME:
                data = json.loads(data.decode('utf-8'))
                if bad_status:
                    raise AcmeError.from_json(data)
            case _:
                if bad_status:
                    raise Exception(
                        f'Bad raw response: status={status} body={data!r}')

        if self.NONCE_HEADER in hdrs:
            self._nonce = hdrs[self.NONCE_HEADER]

        if isinstance(data, dict):
            for h in capture_headers:
                if h in hdrs:
                    data[f'__{h}'] = hdrs[h]

        return data

    @cached_property
    def directory(self) -> dict:
        r = self._resp(self.request(
            'GET', self.directory_url,
            None,
            self._def_hdrs(),
            [self.CTYPE_HEADER]))
        if not isinstance(r, dict):
            raise Exception('Expected json response')
        return r

    def take_nonce(self) -> str:
        if not self._nonce:
            self._resp(self.request(
                'HEAD', self.directory['newNonce'],
                None,
                self._def_hdrs(),
                [self.NONCE_HEADER]))
        n, self._nonce = self._nonce, None
        if n is None:
            raise Exception('Failed to take a nonce')
        return n

    def post(
        self, url: str, data: dict,
        capture_headers: abc.Iterable[str] = (),
        accept_pem_chain: bool = False,
    ) -> dict | bytes:
        h = self._def_hdrs()
        h[self.CTYPE_HEADER] = self.JOSE_JSON_MIME
        if accept_pem_chain:
            h[self.ACCEPT_HEADER] = self.PEM_CHAIN_MIME
        return self._resp(self.request(
            'POST', url,
            bin_json_dumps(data),
            h,
            [self.CTYPE_HEADER, self.NONCE_HEADER, *capture_headers],
        ), capture_headers)


@dataclass
class ProviderAccount:
    contacts: list[str]  # list of urls, including 'mailto:'
    storage_ns: KVNamespace
    https_client: BaseHTTPSClient  # TODO: transform into init-var
    crypto: BaseCrypto
    # on_failure: Callable
    # on_tos_update: Callable
    # this either blocks with error or just notifies about ToS updates
    # no default value on purpose, you have to decide
    # TODO:
    # auto_accept_tos: bool
    auto_create_account: bool = True
    auto_update_account: bool = True

    @cached_property
    def _key_pair(self) -> KeyPairBytes:
        kp = self.storage_ns.get(b'keypair')
        if not kp:
            # TODO: make alg a parameter
            kp = self.crypto.generate_key_pair(Algorithm.ES256)
            self.storage_ns.update({b'keypair': kp})
        if not self.crypto.check_key_pair(kp):
            raise Exception('Invalid key pair')
        return kp

    @cached_property
    def _pubkey_params(self) -> PublicKeyDict:
        return self.crypto.pubkey_params(self._key_pair)

    @cached_property
    def _thumbprint(self) -> str:
        return jwk_thumbprint(self._pubkey_params)

    def _sign_request(self, d: dict) -> None:
        d['signature'] = self.crypto.sign(
            self._key_pair, f"{d['protected']}.{d['payload']}".encode('ascii'))

    def _call_new_account(self, payload: dict) -> AccountDict:
        d = {
            'protected': jws_serialize({
                'alg': 'ES256',  # TODO: alg depends on key_pair used
                'jwk': self._pubkey_params,
                'nonce': self.https_client.take_nonce(),
                'url': self.https_client.directory['newAccount']}),
            'payload': jws_serialize(payload)}
        self._sign_request(d)
        r = cast(AccountDict, self.https_client.post(
            self.https_client.directory['newAccount'], d, ('Location', )))
        if not isinstance(r, dict):
            raise Exception('Expected json response')
        return r

    @cached_property
    def account(self) -> AccountDict:
        try:
            a = self._call_new_account({
                'onlyReturnExisting': True})
        except error.AccountDoesNotExist as e:
            if not self.auto_create_account:
                raise e
            a = self._call_new_account({
                'termsOfServiceAgreed': True,
                'contact': self.contacts})

        if (st := a.get('status')) != 'valid':
            raise Exception(f'Bad account status: {st}')
        if not a.get('__Location'):
            raise Exception('Unknown account location')
        # TODO: update account profile
        # TODO: auto change key algorithm
        return a

    def rollover_key(self) -> None:
        # TODO: implement
        ...

    def deactivate(self) -> None:
        # TODO: implement
        ...

    def _make_protected(self, url: str) -> str:
        return jws_serialize({
            'alg': 'ES256',  # TODO: alg depends on key_pair used
            'kid': self.account['__Location'],
            'nonce': self.https_client.take_nonce(),
            'url': url})

    def _do_signed_request(
        self, url: str,
        payload: dict | str,
        capture_headers: abc.Iterable[str] = (),
    ) -> dict:
        d = {
            'protected': self._make_protected(url),
            'payload': (
                payload
                if isinstance(payload, str) else
                jws_serialize(payload))}
        self._sign_request(d)
        r = self.https_client.post(url, d, capture_headers)
        if not isinstance(r, dict):
            raise Exception('Expected json response')
        return r

    def _download_certificate_request(self, url: str) -> bytes:
        d = {
            'protected': self._make_protected(url),
            'payload': ''}
        self._sign_request(d)
        r = self.https_client.post(url, d, (), accept_pem_chain=True)
        if not isinstance(r, bytes):
            raise Exception('Expected raw bytes response')
        return r


ChallengeConfig = TypedDict('ChallengeConfig', {
    'type': Required[str],
    'url': Required[str],
    'status': Required[str],
    'token': str,
    'issuer-domain-names': list[str],
}, total=False)
AuthzIdentifier = TypedDict('AuthzIdentifier', {
    'type': Required[str],
    'value': Required[str],
}, total=True)


class BaseChallenge:
    TYPE: ClassVar[str] = NotImplemented

    def _perform(
        self,
        identifier: AuthzIdentifier,
        config: ChallengeConfig,
        thumbprint: str,
    ) -> contextlib.AbstractContextManager[None]:
        raise NotImplementedError


class BaseTokenChallenge(BaseChallenge):
    def chal_set(self, name: str, content: str) -> None:
        raise NotImplementedError

    def chal_remove(self, name: str) -> None:
        raise NotImplementedError

    @contextlib.contextmanager
    def _perform(
        self,
        identifier: AuthzIdentifier,
        config: ChallengeConfig,
        thumbprint: str,
    ) -> abc.Iterator[None]:
        token = config['token']
        try:
            self.chal_set(token, f'{token}.{thumbprint}')
            yield
        finally:
            self.chal_remove(token)


def _retry_delay(resp: dict) -> float:
    if (ra := resp.get('__Retry-After', None)):
        return float(ra)
    return 5. + random() * 2.


@dataclass
class CertUpdater:
    # TODO: eventually support IPs
    domains: list[str]
    # TODO: some providers may not support certificate profiles
    # https://letsencrypt.org/docs/profiles/
    # classic (90d) | tlsserver (45d) | shortlived (160h)
    profile: str
    account: ProviderAccount
    challenges: list[BaseChallenge]  # sorted by priority
    storage_ns: KVNamespace
    # deploy: Callable
    # on_failure: Callable

    def _find_chal_performer(
        self, clist: list[ChallengeConfig],
    ) -> tuple[BaseChallenge, ChallengeConfig]:
        for performer in self.challenges:
            for c in clist:
                if c['type'] != performer.TYPE:
                    continue
                if c['status'] != 'pending':
                    continue
                return performer, c
        # TODO: provide more info on available challenge types
        raise Exception('Failed to find suitable challenge performer')

    def _perform_authorization(self, url: str) -> None:
        resp = self.account._do_signed_request(url, '')
        if resp['status'] == 'valid':
            return

        if (st := resp['status']) != 'pending':
            raise Exception(
                f'Authorization must be in status pending, got {st}')
        # TODO: check resp['expires']

        performer, cconf = self._find_chal_performer(resp['challenges'])
        churl = cconf['url']

        with performer._perform(
            resp['identifier'],
            cconf,
            self.account._thumbprint,
        ):
            while True:
                resp = self.account._do_signed_request(
                    churl, {}, ('Retry-After', ))
                match resp['status']:
                    case 'pending' | 'processing':
                        sleep(_retry_delay(resp))
                        continue
                    case 'valid':
                        return
                    case _:
                        raise Exception(f'Invalid challenge: {resp}')

    def _issue_new_certificate(
        self,
        current_order_prefix: bytes = b'current_order/',
    ) -> None:
        storage = self.storage_ns.descend(current_order_prefix)

        # TODO: automatically remove order on error
        # TODO: automatically remove order on domain mismatch

        order_url = storage.get(b'url').decode('utf-8')
        if order_url:
            # get existing order
            # TODO: retry on not found
            order = self.account._do_signed_request(
                order_url, '', ('Retry-After', ))
        else:
            # create new order
            order = self.account._do_signed_request(
                self.account.https_client.directory['newOrder'], {
                    'identifiers': [
                        {'type': 'dns', 'value': d}
                        for d in self.domains],
                    'profile': self.profile,
                }, ('Location', ))
            order_url = order['__Location']
            storage.update({b'url': order_url.encode('utf-8')})

        if order['status'] == 'pending':
            # all authorizations must complete
            # they cover 1-by-1 each domain
            for a in order['authorizations']:
                self._perform_authorization(a)
            # all done, wait order status
            while True:
                order = self.account._do_signed_request(
                    order_url, '', ('Retry-After', ))
                if order['status'] != 'pending':
                    break
                sleep(_retry_delay(order))

        if order['status'] == 'ready':
            kp = self.account.crypto.generate_key_pair(Algorithm.ES256)
            storage.update({b'keypair': kp})
            csr = self.account.crypto.generate_csr(kp, self.domains)
            order = self.account._do_signed_request(order['finalize'], {
                'csr': b64_jose(csr),
            }, ('Retry-After', ))

        while order['status'] == 'processing':
            sleep(_retry_delay(order))
            order = self.account._do_signed_request(
                order_url, '', ('Retry-After', ))

        if order['status'] != 'valid':
            raise Exception(f'Bad order status: {order["status"]}')

        pem_chain = self.account._download_certificate_request(
            order['certificate'])
        storage.update({b'cert_chain': pem_chain})

        print(pem_chain)
