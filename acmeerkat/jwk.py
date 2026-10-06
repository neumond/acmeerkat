import hashlib
import json
from dataclasses import dataclass
from enum import Enum

from .utils import b64_jose, uint_to_bytes


__all__ = (
    'BaseJsonWebPubKey',
    'BaseKeyParams',
    'EcJsonWebPubKey',
    'EcKeyParams',
    'EcType',
    'EdJsonWebPubKey',
    'EdKeyParams',
    'EdVariant',
    'RsaJsonWebPubKey',
    'RsaKeyParams',
    'RsaPssKeyParams',
)


class BaseJsonWebPubKey:
    # rfc7517

    def to_json(self) -> dict[str, str]:
        # used only in .thumbprint method
        raise NotImplementedError

    def thumbprint(self) -> str:
        # JSON Web Key (JWK) Thumbprint, rfc7638
        return b64_jose(hashlib.sha256(json.dumps(
            self.to_json(),
            separators=(',', ':'),
            sort_keys=True,
        ).encode('utf-8')).digest())


class BaseKeyParams:
    pass


class EcType(Enum):
    P_256 = 'P-256'
    P_384 = 'P-384'
    P_521 = 'P-521'  # NOTE: not 512!


@dataclass(frozen=True)
class EcJsonWebPubKey(BaseJsonWebPubKey):
    crv: EcType
    x: bytes
    y: bytes

    def to_json(self) -> dict[str, str]:
        return {
            'kty': 'EC',
            'crv': self.crv.value,
            'x': b64_jose(self.x),
            'y': b64_jose(self.y)}


@dataclass(frozen=True)
class EcKeyParams(BaseKeyParams):
    crv: EcType = EcType.P_256


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
class RsaKeyParams(BaseKeyParams):
    bits: int = 2048
    primes: int = 2
    pubexp: int = 65537


@dataclass(frozen=True)
class RsaPssKeyParams(RsaKeyParams):
    md: str | None = None  # TODO: make enum
    mgf1: str | None = None  # TODO: make enum
    saltlen: int | None = None


class EdVariant(Enum):
    Ed25519 = 'Ed25519'
    Ed448 = 'Ed448'


@dataclass(frozen=True)
class EdJsonWebPubKey(BaseJsonWebPubKey):
    # rfc8037
    crv: EdVariant
    x: bytes

    def to_json(self) -> dict[str, str]:
        return {
            'kty': 'OKP',
            'crv': self.crv.value,
            'x': b64_jose(self.x)}


@dataclass(frozen=True)
class EdKeyParams(BaseKeyParams):
    crv: EdVariant
