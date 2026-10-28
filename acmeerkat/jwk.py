import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from .utils import b64_jose, uint_to_bytes


__all__ = (
    'BaseJsonWebPubKey',
    'EcJsonWebPubKey',
    'EdJsonWebPubKey',
    'RsaJsonWebPubKey',
)


@dataclass(frozen=True)
class BaseJsonWebPubKey:
    """
    RFC7517 JWK
    Just a representation of a public key associated with `private_key`.
    Generally knows nothing about actual signature algorithm,
    which must be stored as `alg_params` near private_key,
    and as `alg` outside jwk in ACME API.
    """

    def to_json(self) -> dict[str, str]:
        raise NotImplementedError

    def thumbprint(self) -> str:
        # JSON Web Key (JWK) Thumbprint, rfc7638
        return b64_jose(hashlib.sha256(json.dumps(
            self.to_json(),
            separators=(',', ':'),
            sort_keys=True,
        ).encode('utf-8')).digest())


@dataclass(frozen=True)
class EcJsonWebPubKey(BaseJsonWebPubKey):
    crv: Literal['P-256', 'P-384', 'P-521']
    x: bytes
    y: bytes

    def to_json(self) -> dict[str, str]:
        return {
            'kty': 'EC',
            'crv': self.crv,
            'x': b64_jose(self.x),
            'y': b64_jose(self.y)}


@dataclass(frozen=True)
class RsaJsonWebPubKey(BaseJsonWebPubKey):
    n: bytes
    e: int

    def to_json(self) -> dict[str, str]:
        return {
            'kty': 'RSA',
            'n': b64_jose(self.n),
            'e': b64_jose(uint_to_bytes(self.e))}


@dataclass(frozen=True)
class EdJsonWebPubKey(BaseJsonWebPubKey):
    "RFC8037 adds OKP key type"
    crv: Literal['Ed25519', 'Ed448']
    x: bytes

    def to_json(self) -> dict[str, str]:
        return {
            'kty': 'OKP',
            'crv': self.crv,
            'x': b64_jose(self.x)}
