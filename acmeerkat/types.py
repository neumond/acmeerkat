from enum import Enum
from typing import Any, Literal, get_args, Required, Self, TypedDict, TypeGuard


__all__ = (
    'AccountDict',
    'AccountStatus',
    'Algorithm',
    'AuthzIdentifier',
    'ChallengeConfig',
    'DirectoryDict',
    'is_valid_account_dict',
    'is_valid_directory_dict',
    'JSONWebSignature',
    'PrivateKey',
)


"""
Rule of thumb for Enum/dataclass vs TypedDict:
If it mostly comes _from_ ACME API, keep it as TypedDict.
Some extra data may come with it, and it's best to keep it as is.
"""


class Algorithm(Enum):
    # rfc7518

    # ES256 required by ACMEv2 for account keys
    # recommended by ACMEv2 for account keys, rfc8037
    # TODO: EdDSA crv=Ed25519

    ES256 = 'ES256'  # ECDSA using P-256 and SHA-256
    ES384 = 'ES384'  # ECDSA using P-384 and SHA-384
    ES512 = 'ES512'  # ECDSA using P-521 and SHA-512

    RS256 = 'RS256'  # RSASSA-PKCS1-v1_5 using SHA-256
    RS384 = 'RS384'  # RSASSA-PKCS1-v1_5 using SHA-384
    RS512 = 'RS512'  # RSASSA-PKCS1-v1_5 using SHA-512

    PS256 = 'PS256'  # RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS384 = 'PS384'  # RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS512 = 'PS512'  # RSASSA-PSS using SHA-512 and MGF1 with SHA-512

    # rfc8037
    EdDSA = 'EdDSA'  # includes Ed25519, Ed448 variants

    # refer to TLS1.3 spec
    # https://datatracker.ietf.org/doc/html/rfc9846#signature-algorithms

    # /* RSASSA-PKCS1-v1_5 algorithms */
    # solely to signatures which appear in certificates
    # rsa_pkcs1_sha256(0x0401),
    # rsa_pkcs1_sha384(0x0501),
    # rsa_pkcs1_sha512(0x0601),

    # /* ECDSA algorithms */
    # ecdsa_secp256r1_sha256(0x0403),
    # ecdsa_secp384r1_sha384(0x0503),
    # ecdsa_secp521r1_sha512(0x0603),

    # /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    # rsa_pss_rsae_sha256(0x0804),
    # rsa_pss_rsae_sha384(0x0805),
    # rsa_pss_rsae_sha512(0x0806),

    # /* EdDSA algorithms */
    # ed25519(0x0807),
    # ed448(0x0808),

    # /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    # rsa_pss_pss_sha256(0x0809),
    # rsa_pss_pss_sha384(0x080a),
    # rsa_pss_pss_sha512(0x080b),

    def to_bytes(self) -> bytes:
        return self.value.encode('ascii')

    @classmethod
    def from_bytes(cls, b: bytes) -> Self:
        return cls(b.decode('ascii'))


# PEM-encoded PKCS#8 private key
type PrivateKey = bytes

# rfc7518
type JSONWebSignature = str


DirectoryDict = TypedDict('DirectoryDict', {
    'newAccount': Required[str],
    'newNonce': Required[str],
    'newOrder': Required[str],
    'keyChange': Required[str],
    # TODO: meta, renewalInfo, revokeCert
}, total=False)


def is_valid_directory_dict(d: dict[str, Any]) -> TypeGuard[DirectoryDict]:
    return (
        isinstance(d, dict)
        and isinstance(d.get('newAccount'), str)
        and isinstance(d.get('newNonce'), str)
        and isinstance(d.get('newOrder'), str)
        and isinstance(d.get('keyChange'), str))


AccountStatus = Literal['valid', 'deactivated', 'revoked']
AccountDict = TypedDict('AccountDict', {
    '__Location': Required[str],
    'status': Required[AccountStatus],
    'contact': list[str],
    'termsOfServiceAgreed': bool,
    # NOTE: required by spec, but omitted on LE
    'orders': str,
    # TODO: externalAccountBinding: dict
    # createdAt: str
    # key: dict
}, total=False)


def is_valid_account_dict(d: dict[str, Any]) -> TypeGuard[AccountDict]:
    return (
        isinstance(d, dict)
        and isinstance(d.get('__Location'), str)
        and d.get('status') in get_args(AccountStatus)
        and ('contact' not in d or (
            isinstance(d['contact'], list)
            and all(isinstance(c, str) for c in d['contact'])))
        and (
            'termsOfServiceAgreed' not in d
            or isinstance(d['termsOfServiceAgreed'], bool))
        and (
            'orders' not in d
            or isinstance(d['orders'], str)))


# TODO: rename to Dict
ChallengeConfig = TypedDict('ChallengeConfig', {
    # TODO: use Literals
    'type': Required[str],
    'url': Required[str],
    'status': Required[str],
    'token': str,
    'issuer-domain-names': list[str],
}, total=False)


# TODO: rename to Dict
AuthzIdentifier = TypedDict('AuthzIdentifier', {
    # TODO: use Literals
    'type': Required[str],
    'value': Required[str],
}, total=True)
