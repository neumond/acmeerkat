from dataclasses import dataclass
from collections import abc
from typing import ClassVar, Self


__all__ = (
    'BaseAlgParams',
    'Ec256',
    'Ec384',
    'Ec512',
    'Ed25519',
    'Ed448',
    'Rsa256',
    'Rsa384',
    'Rsa512',
    'RsaPss256',
    'RsaPss384',
    'RsaPss512',
)


@dataclass(frozen=True)
class BaseAlgParams:
    def get_jws_alg(self) -> str:
        raise NotImplementedError

    _ID_CLS_MAP: ClassVar[dict[bytes, type['BaseAlgParams']]] = {}
    _CLS_ID_MAP: ClassVar[dict[type['BaseAlgParams'], bytes]] = {}

    @classmethod
    def _reg(cls, id: bytes) -> abc.Callable[[type], type]:
        def deco(subcls: type['BaseAlgParams']) -> type['BaseAlgParams']:
            assert issubclass(subcls, cls)
            if id in cls._ID_CLS_MAP:
                raise IndexError
            cls._ID_CLS_MAP[id] = subcls
            if subcls in cls._CLS_ID_MAP:
                raise IndexError
            cls._CLS_ID_MAP[subcls] = id
            return subcls
        return deco

    def _to_bytes_tail(self) -> bytes | None:
        return None

    @classmethod
    def _from_tail(cls, tail: bytes | None) -> Self:
        return cls()

    def to_bytes(self) -> bytes:
        id = self._CLS_ID_MAP[type(self)]
        if (tail := self._to_bytes_tail()) is not None:
            return id + b':' + tail
        return id

    @classmethod
    def from_bytes(cls, b: bytes) -> 'BaseAlgParams':
        bs = b.split(b':', 1)
        subcls = cls._ID_CLS_MAP[bs[0]]
        return subcls._from_tail(bs[1] if len(bs) > 1 else None)


@BaseAlgParams._reg(b'Ec256')
class Ec256(BaseAlgParams):
    "ECDSA using P-256 and SHA-256"

    def get_jws_alg(self) -> str:
        return 'ES256'


@BaseAlgParams._reg(b'Ec384')
class Ec384(BaseAlgParams):
    "ECDSA using P-384 and SHA-384"

    def get_jws_alg(self) -> str:
        return 'ES384'


@BaseAlgParams._reg(b'Ec512')
class Ec512(BaseAlgParams):
    "ECDSA using P-521 and SHA-512"

    def get_jws_alg(self) -> str:
        return 'ES512'


@BaseAlgParams._reg(b'Ed25519')
class Ed25519(BaseAlgParams):
    "EdDSA, Ed25519 variant"

    def get_jws_alg(self) -> str:  # rfc8037
        return 'EdDSA'


@BaseAlgParams._reg(b'Ed448')
class Ed448(BaseAlgParams):
    "EdDSA, Ed448 variant"

    def get_jws_alg(self) -> str:  # rfc8037
        return 'EdDSA'


@dataclass(frozen=True)
class BaseRsaParams(BaseAlgParams):
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

    def _to_bytes_tail(self) -> bytes | None:
        return f'{self.bits}:{self.primes}:{self.pubexp}'.encode('ascii')

    @classmethod
    def _from_tail(cls, tail: bytes | None) -> Self:
        if tail is None:
            raise ValueError
        return cls(*map(int, tail.split(b':')))


@BaseAlgParams._reg(b'Rsa256')
class Rsa256(BaseRsaParams):
    "RSASSA-PKCS1-v1_5 using SHA-256"

    def get_jws_alg(self) -> str:
        return 'RS256'


@BaseAlgParams._reg(b'Rsa384')
class Rsa384(BaseRsaParams):
    "RSASSA-PKCS1-v1_5 using SHA-384"

    def get_jws_alg(self) -> str:
        return 'RS384'


@BaseAlgParams._reg(b'Rsa512')
class Rsa512(BaseRsaParams):
    "RSASSA-PKCS1-v1_5 using SHA-512"

    def get_jws_alg(self) -> str:
        return 'RS512'


@BaseAlgParams._reg(b'RsaPss256')
class RsaPss256(BaseRsaParams):
    "RSASSA-PSS using SHA-256 and MGF1 with SHA-256"

    def get_jws_alg(self) -> str:
        return 'PS256'


@BaseAlgParams._reg(b'RsaPss384')
class RsaPss384(BaseRsaParams):
    "RSASSA-PSS using SHA-384 and MGF1 with SHA-384"

    def get_jws_alg(self) -> str:
        return 'PS384'


@BaseAlgParams._reg(b'RsaPss512')
class RsaPss512(BaseRsaParams):
    "RSASSA-PSS using SHA-512 and MGF1 with SHA-512"

    def get_jws_alg(self) -> str:
        return 'PS512'
