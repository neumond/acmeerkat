import json
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, InitVar
from datetime import datetime, timedelta
from enum import StrEnum
from random import random
from time import sleep
from typing import Any, ClassVar

from .alg_params import BaseAlgParams, Ec256, Ec384
from .utils import (
    b64_jose,
    bin_fromisoformat,
    bin_isoformat,
    bin_json_dumps,
    bin_json_loads,
    bin_optstr_dump,
    bin_optstr_load,
    bin_str_dump,
    bin_str_load,
    is_valid_domain,
    jws_serialize,
    utc_now,
)
from . import abc, error, pem, types as t


__all__ = (
    'Account',
    'CertUpdater',
    'DirectoryUrl',
    'KVNamespace',
)


"""
Let's Encrypt actually differs from RFC8555:
https://raw.githubusercontent.com/letsencrypt/boulder/main/docs/acme-divergences.md
"""


@dataclass(frozen=True)
class KVNamespace:
    storage: abc.BaseKVStorage
    prefix: bytes = b''

    # TODO: rename methods ns_update, ns_get
    # to be incompatible with BaseKVStorage

    def update(self, u: dict[bytes, bytes]) -> None:
        self.storage.update({
            self.prefix + k: v
            for k, v in u.items()})

    def get(self, k: bytes) -> bytes:
        return self.storage.get(self.prefix + k)


@dataclass
class HttpsClientWrap:
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
                    raise error.AcmeError.from_json(data)
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

    def get_directory(self, directory_url: str) -> t.DirectoryDict:
        r = self._resp(self.https_client.request(
            'GET', directory_url,
            None,
            self._def_hdrs(),
            [self.CTYPE_HEADER]))
        if not t.is_valid_directory_dict(r):
            raise ValueError('Invalid directory')
        return r

    def take_nonce(self, new_nonce_url: str) -> str:
        if not self._nonce:
            self._resp(self.https_client.request(
                'HEAD', new_nonce_url,
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


class DirectoryUrl(StrEnum):
    letsencrypt_staging = (
        'https://acme-staging-v02.api.letsencrypt.org/directory')
    letsencrypt = (
        'https://acme-v02.api.letsencrypt.org/directory')


def _autofix_rollover_key(fn: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(self: 'Account', *a: Any, **kw: Any) -> Any:
        while True:
            try:
                r = fn(self, *a, **kw)
            except error.AccountDoesNotExist as e:
                if self._has_rollover_key():
                    self._ns.update(self._switch_to_rollover_key())
                    continue
                raise e
            if self._has_rollover_key():
                self._ns.update(self._drop_rollover_key())
            return r
    return wrapper


@dataclass(frozen=True)
class Account:
    "ACME account"
    id: str
    storage: abc.BaseKVStorage
    https_client: InitVar[abc.BaseHttpsClient]
    crypto: abc.BaseCrypto
    next_alg_params: BaseAlgParams = Ec256()
    accept_language: InitVar[str] = 'en, *;q=0.5'  # localized error messages
    user_agent: InitVar[str] = 'Acmeerkat/0.2'
    ns_template: InitVar[str] = 'account/{id}/'

    _hwrap: HttpsClientWrap = field(init=False)
    _ns: KVNamespace = field(init=False)

    def __post_init__(
        self,
        https_client: abc.BaseHttpsClient,
        accept_language: str,
        user_agent: str,
        ns_template: str,
    ) -> None:
        object.__setattr__(self, '_hwrap', HttpsClientWrap(
            https_client,
            user_agent,
            accept_language))
        object.__setattr__(self, '_ns', KVNamespace(
            self.storage,
            ns_template.format(id=self.id).encode('utf-8')))

    # public properties

    @property
    def directory_url(self) -> str:
        if not (v := self._ns.get(b'directory_url')):
            raise error.NoAccountError
        return bin_str_load(v)

    @property
    def directory(self) -> t.DirectoryDict:
        if not (v := self._ns.get(b'directory')):
            raise error.NoAccountError
        d = bin_json_loads(v)
        if not t.is_valid_directory_dict(d):
            raise ValueError
        return d

    @property
    def alg_params(self) -> BaseAlgParams:
        if not (v := self._ns.get(b'alg_params')):
            raise error.NoAccountError
        return BaseAlgParams.from_bytes(v)

    @property
    def private_key(self) -> bytes:
        if not (v := self._ns.get(b'private_key')):
            raise error.NoAccountError
        return v

    @property
    def key_generated_at(self) -> datetime:
        if not (v := self._ns.get(b'key_generated_at')):
            raise error.NoAccountError
        return bin_fromisoformat(v)

    @property
    def contacts(self) -> tuple[str, ...]:
        if not (v := self._ns.get(b'contacts')):
            raise error.NoAccountError
        cc = bin_json_loads(v)
        if not isinstance(cc, list) or not all(isinstance(c, str) for c in cc):
            raise ValueError
        return tuple(cc)

    @property
    def agreed_to_tos(self) -> datetime:
        if not (v := self._ns.get(b'agreed_to_tos')):
            raise error.NoAccountError
        return bin_fromisoformat(v)

    @property
    def account_url(self) -> str:
        if not (v := self._ns.get(b'account_url')):
            raise error.NoAccountError
        return bin_str_load(v)

    @property
    def account(self) -> t.AccountDict:
        if not (v := self._ns.get(b'account')):
            raise error.NoAccountError
        a = bin_json_loads(v)
        if not t.is_valid_account_dict(a):
            raise ValueError
        return a

    # protected methods

    def _has_rollover_key(self) -> bool:
        return bool(self._ns.get(b'rollover/private_key'))

    def _drop_rollover_key(self) -> dict[bytes, bytes]:
        return {
            b'rollover/alg_params': b'',
            b'rollover/private_key': b'',
            b'rollover/key_generated_at': b''}

    def _switch_to_rollover_key(self) -> dict[bytes, bytes]:
        r = {
            b'alg_params': self._ns.get(b'rollover/alg_params'),
            b'private_key': self._ns.get(b'rollover/private_key'),
            b'key_generated_at': self._ns.get(b'rollover/key_generated_at'),
            **self._drop_rollover_key()}
        if not (
            r[b'alg_params'] and r[b'private_key'] and r[b'key_generated_at']
        ):
            raise Exception(
                'Prevented unwanted key erasure; this is a bug in ACMEerkat')
        return r

    def _sign_with_alg_key(
        self, protected: str, payload: str,
        alg_params: BaseAlgParams, kp: t.PrivateKey,
    ) -> str:
        return b64_jose(self.crypto.sign(
            alg_params, kp, f'{protected}.{payload}'.encode('ascii')))

    def _sign_request(self, d: dict[Any, Any]) -> None:
        d['signature'] = self._sign_with_alg_key(
            d['protected'], d['payload'], self.alg_params, self.private_key)

    @_autofix_rollover_key
    def _call_new_account(self, payload: dict[Any, Any]) -> t.AccountDict:
        directory = self.directory
        jwk = self.crypto.json_web_pub_key(self.private_key)
        d = {
            'protected': jws_serialize({
                'alg': self.alg_params.get_jws_alg(),
                'jwk': jwk.to_json(),
                'nonce': self._hwrap.take_nonce(directory['newNonce']),
                'url': directory['newAccount']}),
            'payload': jws_serialize(payload)}
        self._sign_request(d)
        r = self._hwrap.post(
            directory['newAccount'], d, ('Location', ))
        if not t.is_valid_account_dict(r):
            raise ValueError
        return r

    def _acc_update(self, acc: dict[Any, Any]) -> dict[bytes, bytes]:
        upd = {}
        if '__Location' in acc:
            upd[b'account_url'] = bin_str_dump(acc.pop('__Location'))
        if not t.is_valid_account_dict(acc):
            raise ValueError(f'Invalid account data: {acc!r}')
        upd[b'account'] = bin_json_dumps(acc)
        return upd

    def _make_protected(self, url: str) -> str:
        return jws_serialize({
            'alg': self.alg_params.get_jws_alg(),
            'kid': self.account_url,
            'nonce': self._hwrap.take_nonce(self.directory['newNonce']),
            'url': url})

    # half-protected methods, used by CertUpdater

    def _do_signed_request_no_fix(
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

    @_autofix_rollover_key
    def _do_signed_request(
        self, url: str,
        payload: dict[Any, Any] | str,
        capture_headers: Iterable[str] = (),
    ) -> dict[Any, Any]:
        return self._do_signed_request_no_fix(url, payload, capture_headers)

    @_autofix_rollover_key
    def _download_certificate_request(self, url: str) -> bytes:
        d = {
            'protected': self._make_protected(url),
            'payload': ''}
        self._sign_request(d)
        r = self._hwrap.post(url, d, (), accept_pem_chain=True)
        if not isinstance(r, bytes):
            raise Exception('Expected raw bytes response')
        return r

    def _get_thumbprint(self) -> str:
        jwk = self.crypto.json_web_pub_key(self.private_key)
        return jwk.thumbprint()

    # public methods

    def will_change_any(self, alg_params: bool = False) -> bool:
        try:
            if alg_params and (self.next_alg_params != self.alg_params):
                return True
        except error.NoAccountError:
            return True
        return False

    def get_key_age(self, now: datetime | None = None) -> timedelta:
        try:
            return (utc_now() if now is None else now) - self.key_generated_at
        except error.NoAccountError:
            return timedelta(0)

    def exists(self) -> bool:
        "Check if account exists (can read properties)"
        return self.account is not None

    def is_valid(self) -> bool:
        "Check if account exists and is valid (can issue certificates)"
        account = self.account
        if account is None:
            return False
        return account['status'] == 'valid'

    def refresh(self, directory: bool = True, account: bool = True) -> None:
        """
        Refresh directory and account data from API
        Does nothing if not registered
        """
        upd = {}
        if directory and (du := self.directory_url) is not None:
            upd[b'directory'] = bin_json_dumps(self._hwrap.get_directory(du))
        if account and self.private_key is not None:
            a_json = self._call_new_account({'onlyReturnExisting': True})
            upd[b'account_url'] = bin_str_dump(a_json.pop('__Location'))
            upd[b'account'] = bin_json_dumps(a_json)
        if upd:
            self._ns.update(upd)

    def register(
        self,
        directory_url: DirectoryUrl | str,
        contacts: tuple[str, ...] = (),
        agree_to_tos: bool = True,
    ) -> None:
        """
        Register new account

        Throws error if current account exists and is not deactivated

        Valid `alg_params` as of oct 2026 on LE Staging:
        RS256 (at least 2048 bits), ES256, ES384, ES512

        `contacts` is list of URIs, including 'mailto:' scheme
        NOTE: LE doesn't use or store this field anymore, but it's still in RFC
        """
        if self.is_valid():
            raise error.ValidAccountExists

        upd = {
            b'directory_url': bin_str_dump(directory_url),
            b'alg_params': self.next_alg_params.to_bytes(),
            b'contacts': bin_json_dumps(contacts),
            **self._drop_rollover_key()}

        directory = self._hwrap.get_directory(directory_url)
        upd[b'directory'] = bin_json_dumps(directory)

        kp = self.crypto.generate_key_pair(self.next_alg_params)
        if not self.crypto.check_key_pair(kp):
            raise Exception('Invalid key pair')
        upd[b'private_key'] = kp

        now = bin_isoformat(utc_now())
        upd[b'key_generated_at'] = now
        if agree_to_tos:
            upd[b'agreed_to_tos'] = now

        acc_json = self._call_new_account({
            'termsOfServiceAgreed': agree_to_tos,
            'contact': self.contacts})
        upd[b'account_url'] = bin_str_dump(acc_json.pop('__Location'))
        upd[b'account'] = bin_json_dumps(acc_json)

        self._ns.update(upd)

    def rollover_key(self) -> None:
        "Generate and replace account key pair"
        directory = self.directory
        old_kp = self.private_key
        new_kp = self.crypto.generate_key_pair(self.next_alg_params)
        # store new key nearby, do not rewrite existing key just yet
        self._ns.update({
            b'rollover/alg_params': self.next_alg_params.to_bytes(),
            b'rollover/private_key': new_kp,
            b'rollover/key_generated_at': bin_isoformat(utc_now())})

        inner = {
            'protected': jws_serialize({
                'alg': self.next_alg_params.get_jws_alg(),
                'jwk': self.crypto.json_web_pub_key(new_kp).to_json(),
                'url': directory['keyChange'],
            }),
            'payload': jws_serialize({
                'account': self.account_url,
                'oldKey': self.crypto.json_web_pub_key(old_kp).to_json(),
            })}
        inner['signature'] = self._sign_with_alg_key(
            inner['protected'], inner['payload'],
            self.next_alg_params, new_kp)

        try:
            acc = self._do_signed_request_no_fix(
                directory['keyChange'], inner)
        except (
            error.BadSignatureAlgorithm,  # algorithm not supported
            error.BadPublicKey,  # bad parameters, e.g. low RSA bits
            error.Malformed,  # algorithm-keypair inconsistency
        ) as e:
            self._ns.update(self._drop_rollover_key())
            raise e

        self._ns.update({
            **self._acc_update(acc),
            **self._switch_to_rollover_key()})

    def update_contacts(self, contacts: tuple[str, ...]) -> None:
        acc = self._do_signed_request(
            self.account_url, {'contact': contacts})
        self._ns.update({
            b'contacts': bin_json_dumps(contacts),
            **self._acc_update(acc)})

    def agree_to_tos(self) -> None:
        "Agree again on updated ToS"
        acc = self._do_signed_request(
            self.account_url, {'termsOfServiceAgreed': True})
        self._ns.update({
            b'agreed_to_tos': bin_isoformat(utc_now()),
            **self._acc_update(acc)})

    def deactivate(self, erase_storage: bool = True) -> None:
        acc = self._do_signed_request(
            self.account_url, {'status': 'deactivated'})
        if erase_storage:
            self._ns.update({
                b'directory_url': b'',
                b'directory': b'',
                b'alg_params': b'',
                b'private_key': b'',
                b'key_generated_at': b'',
                b'contacts': b'',
                b'agreed_to_tos': b'',
                b'account_url': b'',
                b'account': b'',
                **self._drop_rollover_key()})
        else:
            self._ns.update(self._acc_update(acc))

    def get_dns_persist_01_record(
        self,
        issuer: str | None = None,
        wildcard: bool = False,
        expires: datetime | None = None,
    ) -> str:
        """
        Craft `_validation-persist.` TXT record for DNS-PERSIST-01 challenge

        Normally autodetects issuer field from directory data,
        but you may override
        """
        parts = []
        if issuer is None:
            directory = self.directory
            if (
                isinstance(meta := directory.get('meta', None), dict)
                and isinstance(caai := meta.get('caaIdentities', None), list)
                and len(caai) > 0
                and isinstance(caai[0], str)
            ):
                issuer = caai[0]
            else:
                raise Exception("Can't detect issuer")
        parts.append(issuer)
        parts.append(f"accounturi={self.account_url}")
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
@dataclass(frozen=True, kw_only=True)
class CertUpdater:
    """
    `next_profile`: None if you don't care, otherwise choose
    from account.directory['meta']['profiles']

    `next_alg_params`: as of oct 2026, LE staging:
    works: Ec256(), Ec384(), Rsa*()
    doesn't work: Ec512(), Ed25519(), Ed448(), RsaPss*()
    rsa key sizes: 2048, 3072, 4096
    """

    id: str
    account: Account

    # TODO: eventually support IPs
    next_domains: tuple[str, ...]
    next_alg_params: BaseAlgParams = Ec384()
    # TODO: some providers may not support certificate profiles
    # https://letsencrypt.org/docs/profiles/
    # classic (90d) | tlsserver (45d) | shortlived (160h)
    next_profile: str | None = None

    # by default, use the same storage as account
    storage: InitVar[abc.BaseKVStorage | None] = None
    ns_template: InitVar[str] = 'cert/{id}/'
    _ns: KVNamespace = field(init=False)

    _CURRENT_ORDER_PREFIX: ClassVar[bytes] = b'current_order/'
    _LATEST_KEY: ClassVar[bytes] = b'latest'

    def __post_init__(
        self,
        storage: abc.BaseKVStorage | None,
        ns_template: str,
    ) -> None:
        for d in self.next_domains:
            if not is_valid_domain(d):
                raise ValueError(
                    f'Invalid domain {d!r}, convert IDN into punycode')
        if storage is None:
            storage = self.account.storage
        object.__setattr__(self, '_ns', KVNamespace(
            storage,
            ns_template.format(id=self.id).encode('utf-8')))

    def _find_chal_performer(
        self,
        challenges: tuple[abc.BaseChallenge, ...],
        clist: list[t.ChallengeConfig],
    ) -> tuple[abc.BaseChallenge, t.ChallengeConfig]:
        for performer in challenges:
            for c in clist:
                if c['type'] != performer.TYPE:
                    continue
                if c['status'] != 'pending':
                    continue
                return performer, c
        have = [p.TYPE for p in challenges]
        got = [c['type'] for c in clist]
        raise error.NoChallengeSolver(
            'Failed to find suitable challenge performer: '
            f'have={have!r} got={got!r}')

    def _perform_authorization(
        self,
        challenges: tuple[abc.BaseChallenge, ...],
        url: str,
        account_thumbprint: str,
    ) -> None:
        resp = self.account._do_signed_request(url, '')
        if resp['status'] == 'valid':
            # already complete
            return

        if (st := resp['status']) != 'pending':
            raise Exception(
                f'Authorization must be in status pending, got {st}')
        # TODO: check resp['expires']

        try:
            performer, cconf = self._find_chal_performer(
                challenges,
                resp['challenges'])
        except error.NoChallengeSolver as e:
            self.account._do_signed_request(url, {
                'status': 'deactivated'})
            raise e

        with performer._perform(
            resp['identifier'],
            cconf,
            account_thumbprint,
        ):
            # initiate challenge
            resp = self.account._do_signed_request(
                cconf['url'], {}, ('Retry-After', ))
            sleep(_retry_delay(resp))
            # polling loop
            while True:
                resp = self.account._do_signed_request(
                    url, '', ('Retry-After', ))
                match resp['status']:
                    case 'pending' | 'processing':
                        sleep(_retry_delay(resp))
                        continue
                    case 'valid':
                        return
                    case _:
                        raise error.ChallengeError(f'Invalid state: {resp!r}')

    def _co_key(self, k: bytes) -> bytes:
        return self._CURRENT_ORDER_PREFIX + k

    def _co_clear(self) -> dict[bytes, bytes]:
        return {
            self._co_key(b'url'): b'',
            self._co_key(b'profile'): b'',
            self._co_key(b'alg_params'): b'',
            self._co_key(b'private_key'): b''}

    def issue_new_certificate(
        self, challenges: tuple[abc.BaseChallenge, ...],
    ) -> None:
        # TODO: automatically remove order on error
        # TODO: automatically remove order on domain mismatch

        directory = self.account.directory

        order_url = bin_str_load(self._ns.get(self._co_key(b'url')))
        if order_url:
            # get existing order
            # TODO: retry on not found
            order = self.account._do_signed_request(
                order_url, '', ('Retry-After', ))
        else:
            # create new order
            order = self.account._do_signed_request(
                directory['newOrder'], {
                    'identifiers': [
                        {'type': 'dns', 'value': d}
                        for d in self.next_domains],
                    'profile': self.next_profile,
                }, ('Location', ))
            order_url = order['__Location']
            self._ns.update({
                self._co_key(b'url'): bin_str_dump(order_url),
                self._co_key(b'profile'): bin_optstr_dump(self.next_profile)})

        if order['status'] == 'pending':
            # all authorizations must complete
            # they cover 1-by-1 each domain
            account_thumbprint = self.account._get_thumbprint()
            try:
                for a in order['authorizations']:
                    self._perform_authorization(
                        challenges, a, account_thumbprint)
            except (error.AcmeError, error.ChallengeError) as e:
                self._ns.update(self._co_clear())
                raise e
            # all done, wait order status
            while True:
                order = self.account._do_signed_request(
                    order_url, '', ('Retry-After', ))
                if order['status'] != 'pending':
                    break
                sleep(_retry_delay(order))

        if order['status'] == 'ready':
            kp = self.account.crypto.generate_key_pair(self.next_alg_params)
            self._ns.update({
                self._co_key(b'alg_params'): self.next_alg_params.to_bytes(),
                self._co_key(b'private_key'): kp})
            csr = self.account.crypto.generate_csr(
                self.next_alg_params, kp, self.next_domains)
            order = self.account._do_signed_request(order['finalize'], {
                'csr': b64_jose(csr),
            }, ('Retry-After', ))

        while order['status'] == 'processing':
            sleep(_retry_delay(order))
            order = self.account._do_signed_request(
                order_url, '', ('Retry-After', ))

        if order['status'] != 'valid':
            self._ns.update(self._co_clear())
            raise error.InvalidOrder(f'Bad order status: {order["status"]}')

        pem_chain = self.account._download_certificate_request(
            order['certificate'])

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

        latest = self._ns.get(self._LATEST_KEY) or b'0'
        bundle = pem.CertBundle(
            prev=latest,
            alg_params=BaseAlgParams.from_bytes(
                self._ns.get(self._co_key(b'alg_params'))),
            profile=bin_optstr_load(self._ns.get(self._co_key(b'profile'))),
            private_key=self._ns.get(self._co_key(b'private_key')),
            cert_chain=tuple(pem.split_pem_concat(pem_chain)),
        )._pack()
        version = str(int(latest) + 1).encode('ascii')
        self._ns.update({
            version: bundle,
            self._LATEST_KEY: version,
            **self._co_clear()})

    def has_unfinished_order(self) -> bool:
        return self._ns.get(self._co_key(b'url')) != b''

    def cancel_current_order(self) -> None:
        # TODO: test this
        order_url = bin_str_load(self._ns.get(self._co_key(b'url')))
        if order_url:
            order = self.account._do_signed_request(
                order_url, '', ('Retry-After', ))
            if order['status'] == 'pending':
                for url in order['authorizations']:
                    self.account._do_signed_request(url, {
                        'status': 'deactivated'})
        self._ns.update(self._co_clear())

    def get_bundle(self, version: bytes | None = None) -> pem.CertBundle:
        if version is None:
            version = self._ns.get(self._LATEST_KEY)
        if not version or not (bundle := self._ns.get(version)):
            raise IndexError('No certificate bundle found')
        return pem.CertBundle._unpack(bundle)

    def iter_bundles(self) -> Iterator[pem.CertBundle]:
        version = self._ns.get(self._LATEST_KEY)
        while (bundle := self._ns.get(version)):
            cb = pem.CertBundle._unpack(bundle)
            version = cb.prev
            yield cb

    def will_change_any(
        self,
        domains: bool = False,
        alg_params: bool = False,
        profile: bool = False,
    ) -> bool:
        try:
            bundle = self.get_bundle()
        except IndexError:
            return True
        if domains and (
            set(self.next_domains)
            != set(bundle.get_leaf_cert_info().domains)
        ):
            return True
        if alg_params and (self.next_alg_params != bundle.alg_params):
            return True
        if profile and (
            self.next_profile is not None
            and self.next_profile != bundle.profile
        ):
            return True
        return False

    def get_remaining_validity(self, now: datetime | None = None) -> timedelta:
        try:
            bundle = self.get_bundle()
        except IndexError:
            return timedelta(0)
        return bundle.get_leaf_cert_info().not_after - (
            utc_now() if now is None else now)
