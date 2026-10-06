import hashlib
import json
from dataclasses import dataclass
from enum import Enum

from .utils import b64_jose, uint_to_bytes


__all__ = (
    'BaseJsonWebPubKey',
    'BaseKeyParams',
    'CurveType',
    'EcJsonWebPubKey',
    'EcKeyParams',
    'EdDsaVariant',
    'EdJsonWebPubKey',
    'EdKeyParams',
    'RsaJsonWebPubKey',
    'RsaKeyParams',
    'RsaPssKeyParams',
)


class BaseJsonWebPubKey:
    # rfc7517
    # TODO: remove thumbprint parameter
    def to_json(self, thumbprint: bool) -> dict[str, str]:
        raise NotImplementedError


class BaseKeyParams:
    pass


class CurveType(Enum):
    P_256 = 'P-256'
    P_384 = 'P-384'
    P_521 = 'P-521'  # NOTE: not 512!


@dataclass
class EcJsonWebPubKey(BaseJsonWebPubKey):
    crv: CurveType
    x: bytes
    y: bytes

    def to_json(self, thumbprint: bool) -> dict[str, str]:
        return {
            'kty': 'EC',
            'crv': self.crv.value,
            'x': b64_jose(self.x),
            'y': b64_jose(self.y),
        }


# TODO: make all KeyParams frozen
@dataclass
class EcKeyParams(BaseKeyParams):
    crv: CurveType = CurveType.P_256


@dataclass
class RsaJsonWebPubKey(BaseJsonWebPubKey):
    n: bytes
    e: int

    def to_json(self, thumbprint: bool) -> dict[str, str]:
        return {
            'kty': 'RSA',
            'n': b64_jose(self.n),
            'e': b64_jose(uint_to_bytes(self.e)),
        }


@dataclass
class RsaKeyParams(BaseKeyParams):
    bits: int = 2048
    primes: int = 2
    pubexp: int = 65537


@dataclass
class RsaPssKeyParams(RsaKeyParams):
    md: str | None = None  # TODO: make enum
    mgf1: str | None = None  # TODO: make enum
    saltlen: int | None = None


class EdDsaVariant(Enum):
    Ed25519 = 'Ed25519'
    Ed448 = 'Ed448'


@dataclass
class EdJsonWebPubKey(BaseJsonWebPubKey):
    # rfc8037
    crv: EdDsaVariant
    x: bytes

    def to_json(self, thumbprint: bool) -> dict[str, str]:
        return {
            'kty': 'OKP',
            'crv': self.crv.value,
            'x': b64_jose(self.x),
        }


@dataclass
class EdKeyParams(BaseKeyParams):
    crv: EdDsaVariant


def thumbprint(d: BaseJsonWebPubKey) -> str:
    # JSON Web Key (JWK) Thumbprint, rfc7638
    return b64_jose(hashlib.sha256(json.dumps(
        d.to_json(thumbprint=True),
        separators=(',', ':'),
        sort_keys=True,
    ).encode('utf-8')).digest())
