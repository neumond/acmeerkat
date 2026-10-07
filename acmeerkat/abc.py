import contextlib
from collections import abc
from typing import ClassVar, Literal

from .jwk import BaseJsonWebPubKey, BaseKeyParams
from .types import (
    Algorithm, AuthzIdentifier, ChallengeConfig,
    KeyPairBytes, PemPrivKey)


__all__ = (
    'BaseChallenge',
    'BaseCrypto',
    'BaseHttpsClient',
    'BaseKVStorage',
    'BaseTokenChallenge',
)


class BaseKVStorage:
    def update(self, u: dict[bytes, bytes]) -> None:
        """
        Should be transactional: apply all or nothing
        Assigning empty value b'' deletes the key
        """
        raise NotImplementedError

    def get(self, k: bytes) -> bytes:
        "Non-existent key yields b''"
        raise NotImplementedError


class BaseHttpsClient:
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
        If resp header doesn't exist, omit the entry in result.

        return_headers should never deal with repeating headers.
        """
        raise NotImplementedError


class BaseCrypto:
    def generate_key_pair(self, params: BaseKeyParams) -> KeyPairBytes:
        raise NotImplementedError

    def check_key_pair(self, key_pair: KeyPairBytes) -> bool:
        raise NotImplementedError

    def json_web_pub_key(self, key_pair: KeyPairBytes) -> BaseJsonWebPubKey:
        raise NotImplementedError

    def pem_private_key(self, key_pair: KeyPairBytes) -> PemPrivKey:
        raise NotImplementedError

    def sign(
        self, alg: Algorithm, key_pair: KeyPairBytes, data: bytes,
    ) -> bytes:
        # suitable for rfc7518 json web signature, but without b64 encoding
        raise NotImplementedError

    def generate_csr(
        self, alg: Algorithm, key_pair: KeyPairBytes, domains: list[str],
    ) -> bytes:
        raise NotImplementedError


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
