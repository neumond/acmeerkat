import hashlib
import json
from dataclasses import dataclass
from enum import Enum

from .types import Algorithm
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
    alg: Algorithm | None = None  # set only for RSA PSS

    def to_json(self) -> dict[str, str]:
        r = {
            'kty': 'RSA',
            'n': b64_jose(self.n),
            'e': b64_jose(uint_to_bytes(self.e))}
        if self.alg is not None:
            r['alg'] = self.alg.value
        return r


@dataclass(frozen=True)
class RsaKeyParams(BaseKeyParams):
    # 2048-bit key provides roughly 112 bits of security,
    # which is considered the standard minimum.
    # For long-term security, 3072-bit or 4096-bit keys are better choices
    bits: int = 2048

    # More primes require more total bits.
    # Multi-prime RSA is not widely supported
    # and offers few practical advantages over standard two-prime RSA.
    # Default of 2 primes is the safest and most compatible choice.
    primes: int = 2

    # You should almost always use the default 65537.
    # It is a large prime with a low Hamming weight
    # (only two bits are set), which balances security
    # with fast encryption and signature verification.
    # Smaller values like 3 are faster
    # but can be less secure in certain contexts
    pubexp: int = 65537

    def __post_init__(self) -> None:
        if self.bits < 512:
            raise ValueError('Too few bits, must be at least 512')

        if self.primes < 2:
            raise ValueError("Can't have less than 2 primes")
        if self.primes > 5:
            raise ValueError("Can't have more than 5 primes")
        at_least_bits = {
            2: 0,
            3: 1024,
            4: 4096,
            5: 8192,
        }[self.primes]
        if self.bits < at_least_bits:
            raise ValueError(
                f'Too few bits for {self.primes} primes: '
                f'need at least {at_least_bits}, got {self.bits}')

        if self.pubexp <= 1 or self.pubexp % 2 == 0:
            raise ValueError('Public exponent must be larger than 1 and odd')


@dataclass(frozen=True)
class RsaPssKeyParams(RsaKeyParams):
    alg: Algorithm = Algorithm.PS256

    def __post_init__(self) -> None:
        if self.alg not in (
            Algorithm.PS256,
            Algorithm.PS384,
            Algorithm.PS512,
        ):
            raise ValueError('Bad algorithm value, must be PS')


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
