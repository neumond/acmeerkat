import json
from collections.abc import Iterable
from dataclasses import dataclass, field, InitVar
from datetime import datetime, timedelta, timezone
from functools import cached_property
from pathlib import Path
from random import random
from time import sleep
from typing import Any, ClassVar, Self

from .error import AcmeError, ChallengeTypeMismatch, InvalidOrder
from .utils import b64_jose, bin_json_dumps, jws_serialize, is_valid_domain
from . import abc, error, jwk, pem, types as t


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
    ) -> dict[Any, Any] | bytes:
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
        self, url: str, data: dict[Any, Any],
        capture_headers: Iterable[str] = (),
        accept_pem_chain: bool = False,
    ) -> dict[Any, Any] | bytes:
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


def _check_alg_key_params(
    a: t.Algorithm, key_params: jwk.BaseKeyParams,
) -> None:
    match a, key_params:
        case (t.Algorithm.ES256, jwk.EcKeyParams(crv=jwk.EcType.P_256)):
            return
        case (t.Algorithm.ES384, jwk.EcKeyParams(crv=jwk.EcType.P_384)):
            return
        case (t.Algorithm.ES512, jwk.EcKeyParams(crv=jwk.EcType.P_521)):
            return
        case (t.Algorithm.EdDSA, jwk.EdKeyParams()):
            return
        case (
            t.Algorithm.RS256 | t.Algorithm.RS384 | t.Algorithm.RS512,
            jwk.RsaKeyParams(),
        ) if not isinstance(key_params, jwk.RsaPssKeyParams):
            return
        case (t.Algorithm.PS256, jwk.RsaPssKeyParams(alg=t.Algorithm.PS256)):
            return
        case (t.Algorithm.PS384, jwk.RsaPssKeyParams(alg=t.Algorithm.PS384)):
            return
        case (t.Algorithm.PS512, jwk.RsaPssKeyParams(alg=t.Algorithm.PS512)):
            return
    raise ValueError(
        'Invalid combination of Algorithm and KeyParams: '
        f'{a} + {key_params}')


# too many parameters to guarantee stable order, therefore kw_only
@dataclass(kw_only=True)
class ProviderAccount:
    directory_url: InitVar[str]
    storage_ns: KVNamespace
    https_client: InitVar[abc.BaseHttpsClient]
    crypto: abc.BaseCrypto

    # list of URIs, possibly with 'mailto:' scheme
    # NOTE: LE doesn't use or store this field anyway
    contacts: list[str] = field(default_factory=list)
    auto_create_account: bool = True

    # parameters for account key pair
    # used on account creation or key rollover
    # otherwise latest data from storage wins
    #
    # As of oct 2026 on LE Staging:
    # Unable to validate JWS ... expected one of [RS256 ES256 ES384 ES512]
    # Unable to validate JWS ... (RSA) key size not supported: 1024
    # RS256 + 2048: fine
    alg: t.Algorithm = t.Algorithm.ES256
    key_params: jwk.BaseKeyParams = field(
        default_factory=lambda: jwk.EcKeyParams(crv=jwk.EcType.P_256))

    user_agent: InitVar[str] = 'Acmeerkat/0.1'
    accept_language: InitVar[str] = 'en, *;q=0.5'  # localized error messages

    _hwrap: HttpsClientWrap = field(init=False)

    def __post_init__(
        self,
        directory_url: str,
        https_client: abc.BaseHttpsClient,
        user_agent: str,
        accept_language: str,
    ) -> None:
        _check_alg_key_params(self.alg, self.key_params)
        self._hwrap = HttpsClientWrap(
            directory_url,
            https_client,
            user_agent,
            accept_language)

    @cached_property
    def _key_pair(self) -> t.PrivateKey:
        kp = self.storage_ns.get(b'keypair')
        if not kp:
            if not self.auto_create_account:
                raise Exception(
                    'No account key available, turn on auto_create_account')
            kp = self.crypto.generate_key_pair(self.key_params)
            self.storage_ns.update({
                b'alg': self.alg.to_bytes(),
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
        return self._json_web_pub_key.thumbprint()

    def _reload_alg_key(self) -> None:
        try:
            del self._key_pair
        except AttributeError:
            pass
        try:
            del self._alg
        except AttributeError:
            pass
        try:
            del self._json_web_pub_key
        except AttributeError:
            pass
        try:
            del self._thumbprint
        except AttributeError:
            pass

    def _has_rollover_key(self) -> bool:
        return bool(self.storage_ns.get(b'rollover/keypair'))

    def _drop_rollover_key(self) -> None:
        self.storage_ns.update({
            b'rollover/alg': b'',
            b'rollover/keypair': b''})

    def _switch_to_rollover_key(self) -> None:
        self.storage_ns.update({
            b'alg': self.storage_ns.get(b'rollover/alg'),
            b'keypair': self.storage_ns.get(b'rollover/keypair'),
            b'rollover/alg': b'',
            b'rollover/keypair': b''})
        self._reload_alg_key()

    def _sign_with_alg_key(
        self, protected: str, payload: str,
        alg: t.Algorithm, kp: t.PrivateKey,
    ) -> str:
        return b64_jose(self.crypto.sign(
            alg, kp, f'{protected}.{payload}'.encode('ascii')))

    def _sign_request(self, d: dict[Any, Any]) -> None:
        d['signature'] = self._sign_with_alg_key(
            d['protected'], d['payload'], self._alg, self._key_pair)

    def _call_new_account(self, payload: dict[Any, Any]) -> t.AccountDict:
        d = {
            'protected': jws_serialize({
                'alg': self._alg.value,
                'jwk': self._json_web_pub_key.to_json(),
                'nonce': self._hwrap.take_nonce(),
                'url': self.directory['newAccount']}),
            'payload': jws_serialize(payload)}
        self._sign_request(d)
        r = self._hwrap.post(
            self.directory['newAccount'], d, ('Location', ))
        if not (
            isinstance(r, dict)
            and t.is_valid_account_dict(r)
        ):
            raise ValueError('Invalid account')
        return r

    def _make_protected(self, url: str) -> str:
        return jws_serialize({
            'alg': self._alg.value,
            'kid': self.account['__Location'],
            'nonce': self._hwrap.take_nonce(),
            'url': url})

    def _update_account(self, a: dict[Any, Any]) -> t.AccountDict:
        if '__Location' not in a:
            # account updates do not return Location header
            # filling here old value to pass validation
            a['__Location'] = self.account['__Location']
        if not t.is_valid_account_dict(a):
            raise ValueError(f'Invalid account: {a!r}')
        self.account = a
        return a

    # half-protected methods, used by CertUpdater

    def _do_signed_request(
        self, url: str,
        payload: dict[Any, Any] | str,
        capture_headers: Iterable[str] = (),
    ) -> dict[Any, Any]:
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

    # public methods & properties

    @property
    def directory(self) -> t.DirectoryDict:
        return self._hwrap.directory

    @cached_property
    def account(self) -> t.AccountDict:
        while True:
            try:
                a = self._call_new_account({
                    'onlyReturnExisting': True})
            except error.AccountDoesNotExist as e:
                if self._has_rollover_key():
                    self._switch_to_rollover_key()
                    continue
                if not self.auto_create_account:
                    raise e
                a = self._call_new_account({
                    'termsOfServiceAgreed': True,
                    'contact': self.contacts})
            else:
                if self._has_rollover_key():
                    self._drop_rollover_key()
            break
        if (st := a.get('status')) != 'valid':
            raise Exception(f'Bad account status: {st}')
        if not a.get('__Location'):
            raise Exception('Unknown account location')
        # TODO: update account profile
        return a

    def rollover_key(self) -> t.AccountDict:
        _ = self.account  # preload account before generating new key

        new_alg = self.alg
        new_kp = self.crypto.generate_key_pair(self.key_params)
        # store new key nearby, do not rewrite existing key
        self.storage_ns.update({
            b'rollover/alg': new_alg.to_bytes(),
            b'rollover/keypair': new_kp})

        inner = {
            'protected': jws_serialize({
                'alg': new_alg.value,
                'jwk': self.crypto.json_web_pub_key(new_kp).to_json(),
                'url': self.directory['keyChange'],
            }),
            'payload': jws_serialize({
                'account': self.account['__Location'],
                'oldKey': self._json_web_pub_key.to_json(),
            })}
        inner['signature'] = self._sign_with_alg_key(
            inner['protected'], inner['payload'], new_alg, new_kp)

        try:
            resp = self._do_signed_request(
                self.directory['keyChange'],
                inner)
        except (
            error.BadSignatureAlgorithm,  # algorithm not supported
            error.BadPublicKey,  # bad parameters, e.g. low RSA bits
            error.Malformed,  # algorithm-keypair inconsistency
        ) as e:
            self._drop_rollover_key()
            raise e

        self._switch_to_rollover_key()
        return self._update_account(resp)

    def deactivate(self, drop_key: bool = True) -> t.AccountDict:
        resp = self._do_signed_request(
            self.account['__Location'],
            {'status': 'deactivated'})
        if drop_key:
            self.storage_ns.update({
                b'alg': b'',
                b'keypair': b''})
        return self._update_account(resp)

    def update_contacts(self) -> t.AccountDict:
        # NOTE: does nothing on LE
        resp = self._do_signed_request(
            self.account['__Location'],
            {'contact': self.contacts})
        return self._update_account(resp)

    def update_tos_agreement(self, agreed: bool = True) -> t.AccountDict:
        # NOTE: does nothing on LE, even with agreed=False
        resp = self._do_signed_request(
            self.account['__Location'],
            {'termsOfServiceAgreed': agreed})
        return self._update_account(resp)

    def dns_persist_01_record(
        self, issuer: str = 'letsencrypt.org',
        wildcard: bool = False,
        expires: datetime | None = None,
    ) -> str:
        parts = []
        parts.append(issuer)
        parts.append(f"accounturi={self.account['__Location']}")
        if wildcard:
            parts.append('policy=wildcard')
        if expires:
            parts.append(f'persistUntil={int(expires.timestamp())}')
        return '; '.join(parts)


def _retry_delay(resp: dict[Any, Any]) -> float:
    if (ra := resp.get('__Retry-After', None)):
        return float(ra)
    return 5. + random() * 2.


# too many parameters to guarantee stable order, therefore kw_only
@dataclass(kw_only=True)
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

    # parameters for certificate key pair
    alg: t.Algorithm = t.Algorithm.ES256
    key_params: jwk.BaseKeyParams = field(
        default_factory=lambda: jwk.EcKeyParams(crv=jwk.EcType.P_256))

    _CURRENT_ORDER_PREFIX: ClassVar[bytes] = b'current_order/'
    _LATEST_KEY: ClassVar[bytes] = b'latest'

    def __post_init__(self) -> None:
        _check_alg_key_params(self.alg, self.key_params)
        for d in self.domains:
            if not is_valid_domain(d):
                raise ValueError(
                    f'Invalid domain {d!r}, convert IDN into punycode')

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
        have = [p.TYPE for p in self.challenges]
        got = [c['type'] for c in clist]
        raise ChallengeTypeMismatch(
            'Failed to find suitable challenge performer: '
            f'have={have!r} got={got!r}')

    def _perform_authorization(self, url: str) -> None:
        resp = self.account._do_signed_request(url, '')
        if resp['status'] == 'valid':
            return

        if (st := resp['status']) != 'pending':
            raise Exception(
                f'Authorization must be in status pending, got {st}')
        # TODO: check resp['expires']

        try:
            performer, cconf = self._find_chal_performer(resp['challenges'])
        except ChallengeTypeMismatch as e:
            self.account._do_signed_request(url, {
                'status': 'deactivated'})
            raise e

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

    def _store_new_bundle(self) -> None:
        """
        Linked list structure with invalid tail pointer
        Every certificate+keypair is a single binary
        with little header.

        latest: 315
        315: prev=310 alg=ES256 -----BEGIN CERTIFICATE...
        310: prev=294 alg=RS512 -----BEGIN CERTIFICATE...
        294: prev=255 alg=RS512 -----BEGIN CERTIFICATE...
        # 255 doesn't exist
        """
        order = self.storage_ns.descend(self._CURRENT_ORDER_PREFIX)
        latest = self.storage_ns.get(self._LATEST_KEY) or b'0'
        bundle = pem.pack_bundle(
            pem_chain=order.get(b'cert_chain'),
            private_key=order.get(b'keypair'),
            header=b'prev=' + latest + b' alg=' + order.get(b'alg'))
        version = str(int(latest) + 1).encode('ascii')
        self.storage_ns.update({
            version: bundle,
            b'latest': version,
            self._CURRENT_ORDER_PREFIX + b'url': b'',
            self._CURRENT_ORDER_PREFIX + b'alg': b'',
            self._CURRENT_ORDER_PREFIX + b'keypair': b'',
            self._CURRENT_ORDER_PREFIX + b'cert_chain': b''})

    def cancel_current_order(self) -> None:
        storage = self.storage_ns.descend(self._CURRENT_ORDER_PREFIX)
        order_url = storage.get(b'url').decode('utf-8')
        if order_url:
            order = self.account._do_signed_request(
                order_url, '', ('Retry-After', ))
            if order['status'] == 'pending':
                for url in order['authorizations']:
                    self.account._do_signed_request(url, {
                        'status': 'deactivated'})
        storage.update({
            b'url': b'',
            b'alg': b'',
            b'keypair': b'',
            b'cert_chain': b''})

    def issue_new_certificate(self) -> None:
        storage = self.storage_ns.descend(self._CURRENT_ORDER_PREFIX)

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
                self.account.directory['newOrder'], {
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
            try:
                for a in order['authorizations']:
                    self._perform_authorization(a)
            except AcmeError as e:
                storage.update({
                    b'url': b'',
                    b'alg': b'',
                    b'keypair': b'',
                    b'cert_chain': b''})
                raise e
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
            storage.update({
                b'url': b'',
                b'alg': b'',
                b'keypair': b'',
                b'cert_chain': b''})
            raise InvalidOrder(f'Bad order status: {order["status"]}')

        pem_chain = self.account._download_certificate_request(
            order['certificate'])
        storage.update({b'cert_chain': pem_chain})
        self._store_new_bundle()

    def get_current_bundle(self) -> bytes:
        latest = self.storage_ns.get(self._LATEST_KEY)
        if not latest:
            raise IndexError('No certificate bundle found')
        bundle = self.storage_ns.get(latest)
        return bundle[bundle.find(b'-----'):]

    def get_remaining_validity(self, now: datetime | None = None) -> timedelta:
        try:
            bundle = self.get_current_bundle()
        except IndexError:
            return timedelta(0)
        cinfo = pem.parse_bundle_cert_info(bundle)
        return cinfo.not_after - (
            datetime.now(timezone.utc)
            if now is None else now)

    def write_nginx_files(
        self, cert_chain: Path | str,
        private_key: Path | str,
    ) -> None:
        if isinstance(cert_chain, str):
            cert_chain = Path(cert_chain)
        if isinstance(private_key, str):
            private_key = Path(private_key)
        cert = []
        pk = b''
        for part in pem.split_pem_bundle(self.get_current_bundle()):
            ptype, _ = pem.pem_object_split(part)
            match ptype:
                case b'CERTIFICATE':
                    cert.append(part)
                case b'PRIVATE KEY':
                    pk = part
        cert_chain.write_bytes(b'\n\n'.join(cert))
        private_key.write_bytes(pk)

    def write_haproxy_file(self, path: Path | str) -> None:
        if isinstance(path, str):
            path = Path(path)
        path.write_bytes(self.get_current_bundle())
