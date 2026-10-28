from dataclasses import dataclass
from typing import Any, Callable, ClassVar


@dataclass
class AcmeError(Exception):
    detail: str
    subproblems: list[Any] | None = None

    _SUBCLS_MAP: ClassVar[dict[str, type['AcmeError']]] = {}
    _TYPE_PREFIX: ClassVar[str] = 'urn:ietf:params:acme:error:'

    @classmethod
    def _reg(cls, err_type: str) -> Callable[[type], type]:
        def deco(subcls: type['AcmeError']) -> type['AcmeError']:
            assert issubclass(subcls, cls)
            cls._SUBCLS_MAP[err_type] = subcls
            return subcls
        return deco

    @classmethod
    def from_json(cls, j: dict[Any, Any]) -> 'AcmeError':
        t = j.get('type', '')
        if not t.startswith(cls._TYPE_PREFIX):
            raise Exception(f'Not a valid acme error: {j}')
        st = t.removeprefix(cls._TYPE_PREFIX)
        detail = j.get('detail', '')
        subproblems = j.get('subproblems', None)
        if st not in cls._SUBCLS_MAP:
            return cls(f'{detail} {t}', subproblems)
        return cls._SUBCLS_MAP[st](detail, subproblems)


@AcmeError._reg('accountDoesNotExist')
class AccountDoesNotExist(AcmeError):
    "The request specified an account that does not exist"


@AcmeError._reg('alreadyRevoked')
class AlreadyRevoked(AcmeError):
    """
    The request specified a certificate to be revoked
    that has already been revoked
    """


@AcmeError._reg('badCSR')
class BadCSR(AcmeError):
    "The CSR is unacceptable (e.g., due to a short key)"


@AcmeError._reg('badNonce')
class BadNonce(AcmeError):
    "The client sent an unacceptable anti-replay nonce"


@AcmeError._reg('badPublicKey')
class BadPublicKey(AcmeError):
    "The JWS was signed by a public key the server does not support"


@AcmeError._reg('badRevocationReason')
class BadRevocationReason(AcmeError):
    "The revocation reason provided is not allowed by the server"


@AcmeError._reg('badSignatureAlgorithm')
class BadSignatureAlgorithm(AcmeError):
    "The JWS was signed with an algorithm the server does not support"


@AcmeError._reg('caa')
class Caa(AcmeError):
    """
    Certification Authority Authorization (CAA) records
    forbid the CA from issuing a certificate
    """


@AcmeError._reg('compound')
class Compound(AcmeError):
    "Specific error conditions are indicated in the \"subproblems\" array"


@AcmeError._reg('connection')
class Connection(AcmeError):
    "The server could not connect to validation target"


@AcmeError._reg('dns')
class Dns(AcmeError):
    "There was a problem with a DNS query during identifier validation"


@AcmeError._reg('externalAccountRequired')
class ExternalAccountRequired(AcmeError):
    "The request must include a value for the \"externalAccountBinding\" field"


@AcmeError._reg('incorrectResponse')
class IncorrectResponse(AcmeError):
    "Response received didn't match the challenge's requirements"


@AcmeError._reg('invalidContact')
class InvalidContact(AcmeError):
    "A contact URL for an account was invalid"


@AcmeError._reg('malformed')
class Malformed(AcmeError):
    "The request message was malformed"


@AcmeError._reg('orderNotReady')
class OrderNotReady(AcmeError):
    """
    The request attempted to finalize an order
    that is not ready to be finalized
    """


@AcmeError._reg('rateLimited')
class RateLimited(AcmeError):
    "The request exceeds a rate limit"


@AcmeError._reg('rejectedIdentifier')
class RejectedIdentifier(AcmeError):
    "The server will not issue certificates for the identifier"


@AcmeError._reg('serverInternal')
class ServerInternal(AcmeError):
    "The server experienced an internal error"


@AcmeError._reg('tls')
class Tls(AcmeError):
    "The server received a TLS error during validation"


@AcmeError._reg('unauthorized')
class Unauthorized(AcmeError):
    "The client lacks sufficient authorization"


@AcmeError._reg('unsupportedContact')
class UnsupportedContact(AcmeError):
    "A contact URL for an account used an unsupported protocol scheme"


@AcmeError._reg('unsupportedIdentifier')
class UnsupportedIdentifier(AcmeError):
    "An identifier is of an unsupported type"


@AcmeError._reg('userActionRequired')
class UserActionRequired(AcmeError):
    "Visit the \"instance\" URL and take actions specified there"


# non-API errors


class NoChallengeSolver(Exception):
    "Can't find supported challenge type"


class InvalidOrder(Exception):
    "Order has status `invalid`"


class ValidAccountExists(Exception):
    "Can't register on top of existing account"


class NoAccountError(Exception):
    "Account haven't been created yet"


class ChallengeError(Exception):
    "Failed to fulfill the challenge"
