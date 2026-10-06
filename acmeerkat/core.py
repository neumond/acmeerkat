import json
from collections.abc import Iterable
from dataclasses import dataclass, field, InitVar
from functools import cached_property
from random import random
from time import sleep
from typing import ClassVar, Self

from .error import AcmeError
from .utils import b64_jose, bin_json_dumps, jws_serialize
from . import abc, error, jwk, types as t


__all__ = (
    'CertUpdater',
    'KVNamespace',
    'ProviderAccount',
)


"""
Let's Encrypt actually differs from RFC8555:
https://raw.githubusercontent.com/letsencrypt/boulder/main/docs/acme-divergences.md
"""


@dataclass
class KVNamespace:
    storage: abc.BaseKVStorage
    prefix: bytes = b''

    def update(self, u: dict[bytes, bytes]) -> None:
        return self.storage.update({
            self.prefix + k: v
            for k, v in u.items()})

    def get(self, k: bytes) -> bytes:
        return self.storage.get(self.prefix + k)

    def descend(self, prefix: bytes) -> Self:
        return type(self)(self.storage, self.prefix + prefix)


@dataclass
class HttpsClientWrap:
    directory_url: str
    https_client: abc.BaseHttpsClient
    user_agent: str
    accept_language: str

    _nonce: str | None = field(init=False, default=None)

    JSON_MIME: ClassVar[str] = 'application/json'
    PROBLEM_JSON_MIME: ClassVar[str] = 'application/problem+json'
    JOSE_JSON_MIME: ClassVar[str] = 'application/jose+json'
    PEM_CHAIN_MIME: ClassVar[str] = 'application/pem-certificate-chain'
    NONCE_HEADER: ClassVar[str] = 'Replay-Nonce'
    CTYPE_HEADER: ClassVar[str] = 'Content-Type'
    ACCEPT_HEADER: ClassVar[str] = 'Accept'

    def _def_hdrs(self) -> dict[str, str]:
        return {
            'User-Agent': self.user_agent,
            'Accept-Language': self.accept_language,
        }

    def _resp(
        self,
        r: tuple[int, bytes | None, dict[str, str]],
        capture_headers: Iterable[str] = (),
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
    def directory(self) -> t.DirectoryDict:
        r = self._resp(self.https_client.request(
            'GET', self.directory_url,
            None,
            self._def_hdrs(),
            [self.CTYPE_HEADER]))
        if not (
            isinstance(r, dict)
            and t.is_valid_directory_dict(r)
        ):
            raise ValueError('Invalid directory')
        return r

    def take_nonce(self) -> str:
        if not self._nonce:
            self._resp(self.https_client.request(
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
        capture_headers: Iterable[str] = (),
        accept_pem_chain: bool = False,
    ) -> dict | bytes:
        h = self._def_hdrs()
        h[self.CTYPE_HEADER] = self.JOSE_JSON_MIME
        if accept_pem_chain:
            h[self.ACCEPT_HEADER] = self.PEM_CHAIN_MIME
        return self._resp(self.https_client.request(
            'POST', url,
            bin_json_dumps(data),
            h,
            [self.CTYPE_HEADER, self.NONCE_HEADER, *capture_headers],
        ), capture_headers)


@dataclass
class ProviderAccount:
    directory_url: InitVar[str]
    contacts: list[str]  # list of urls, including 'mailto:'
    storage_ns: KVNamespace
    https_client: InitVar[abc.BaseHttpsClient]
    crypto: abc.BaseCrypto

    user_agent: InitVar[str] = 'Acmeerkat/0.1'
    accept_language: InitVar[str] = 'en, *;q=0.5'  # localized error messages

    # on_failure: Callable
    # on_tos_update: Callable
    # this either blocks with error or just notifies about ToS updates
    # no default value on purpose, you have to decide
    # TODO:
    # auto_accept_tos: bool
    auto_create_account: bool = True
    auto_update_account: bool = True

    _hwrap: HttpsClientWrap = field(init=False)

    def __post_init__(
        self,
        directory_url: str,
        https_client: abc.BaseHttpsClient,
        user_agent: str,
        accept_language: str,
    ):
        self._hwrap = HttpsClientWrap(
            directory_url,
            https_client,
            user_agent,
            accept_language)

    @cached_property
    def _key_pair(self) -> t.KeyPairBytes:
        kp = self.storage_ns.get(b'keypair')
        if not kp:
            # TODO: make a parameter
            kp = self.crypto.generate_key_pair(jwk.EcKeyParams(
                crv=jwk.CurveType.P_256))
            self.storage_ns.update({
                b'alg': t.Algorithm.ES256.to_bytes(),
                b'keypair': kp})
        if not self.crypto.check_key_pair(kp):
            raise Exception('Invalid key pair')
        return kp

    @cached_property
    def _alg(self) -> t.Algorithm:
        _ = self._key_pair  # load key pair
        return t.Algorithm.from_bytes(self.storage_ns.get(b'alg'))

    @cached_property
    def _json_web_pub_key(self) -> jwk.BaseJsonWebPubKey:
        return self.crypto.json_web_pub_key(self._key_pair)

    @cached_property
    def _thumbprint(self) -> str:
        return jwk.thumbprint(self._json_web_pub_key)

    def _sign_request(self, d: dict) -> None:
        d['signature'] = self.crypto.sign(
            self._alg, self._key_pair,
            f"{d['protected']}.{d['payload']}".encode('ascii'))

    def _call_new_account(self, payload: dict) -> t.AccountDict:
        d = {
            'protected': jws_serialize({
                'alg': 'ES256',  # TODO: alg depends on key_pair used
                'jwk': self._json_web_pub_key,
                'nonce': self._hwrap.take_nonce(),
                'url': self._hwrap.directory['newAccount']}),
            'payload': jws_serialize(payload)}
        self._sign_request(d)
        r = self._hwrap.post(
            self._hwrap.directory['newAccount'], d, ('Location', ))
        if not (
            isinstance(r, dict)
            and t.is_valid_account_dict(r)
        ):
            raise ValueError('Invalid account')
        return r

    @cached_property
    def account(self) -> t.AccountDict:
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
            'nonce': self._hwrap.take_nonce(),
            'url': url})

    def _do_signed_request(
        self, url: str,
        payload: dict | str,
        capture_headers: Iterable[str] = (),
    ) -> dict:
        d = {
            'protected': self._make_protected(url),
            'payload': (
                payload
                if isinstance(payload, str) else
                jws_serialize(payload))}
        self._sign_request(d)
        r = self._hwrap.post(url, d, capture_headers)
        if not isinstance(r, dict):
            raise Exception('Expected json response')
        return r

    def _download_certificate_request(self, url: str) -> bytes:
        d = {
            'protected': self._make_protected(url),
            'payload': ''}
        self._sign_request(d)
        r = self._hwrap.post(url, d, (), accept_pem_chain=True)
        if not isinstance(r, bytes):
            raise Exception('Expected raw bytes response')
        return r


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
    challenges: list[abc.BaseChallenge]  # sorted by priority
    storage_ns: KVNamespace
    alg: t.Algorithm = t.Algorithm.ES256
    key_params: jwk.BaseKeyParams = field(
        default_factory=lambda: jwk.EcKeyParams(crv=jwk.CurveType.P_256))
    # deploy: Callable
    # on_failure: Callable

    def _find_chal_performer(
        self, clist: list[t.ChallengeConfig],
    ) -> tuple[abc.BaseChallenge, t.ChallengeConfig]:
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
                self.account._hwrap.directory['newOrder'], {
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
            kp = self.account.crypto.generate_key_pair(self.key_params)
            storage.update({
                b'alg': self.alg.to_bytes(),
                b'keypair': kp})
            csr = self.account.crypto.generate_csr(self.alg, kp, self.domains)
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
