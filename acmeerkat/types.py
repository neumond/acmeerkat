from typing import Any, Literal, get_args, Required, TypedDict, TypeGuard


__all__ = (
    'AccountDict',
    'AccountStatus',
    'AuthzIdentifier',
    'ChallengeConfig',
    'DirectoryDict',
    'is_valid_account_dict',
    'is_valid_directory_dict',
    'JSONWebSignature',
    'PemBase64Body',
    'PemConcat',
    'PemObject',
    'PemTag',
    'PrivateKey',
)


"""
Rule of thumb for Enum/dataclass vs TypedDict:
If it mostly comes _from_ ACME API, keep it as TypedDict.
Some extra data may come with it, and it's best to keep it as is.
"""

# PEM-encoded object, with BEGIN/END armor
type PemObject = bytes

# joined PemObjects, usually using b'\n\n'
type PemConcat = bytes

# object name in armor b'CERTIFICATE', b'PRIVATE KEY'
type PemTag = bytes

# inner content of PemObject
type PemBase64Body = bytes

# PEM-encoded PKCS#8 private key
type PrivateKey = PemObject

# rfc7518
type JSONWebSignature = str


DirectoryDict = TypedDict('DirectoryDict', {
    'newAccount': Required[str],
    'newNonce': Required[str],
    'newOrder': Required[str],
    'keyChange': Required[str],
    # TODO: meta, renewalInfo, revokeCert
}, total=False)


def is_valid_directory_dict(d: Any) -> TypeGuard[DirectoryDict]:
    return (
        isinstance(d, dict)
        and isinstance(d.get('newAccount'), str)
        and isinstance(d.get('newNonce'), str)
        and isinstance(d.get('newOrder'), str)
        and isinstance(d.get('keyChange'), str))


AccountStatus = Literal['valid', 'deactivated', 'revoked']
AccountDict = TypedDict('AccountDict', {
    'status': Required[AccountStatus],
    '__Location': str,
    'contact': list[str],
    'termsOfServiceAgreed': bool,
    # NOTE: required by spec, but omitted on LE
    'orders': str,
    # TODO: externalAccountBinding: dict
    # createdAt: str
    # key: dict
}, total=False)


def is_valid_account_dict(d: Any) -> TypeGuard[AccountDict]:
    return (
        isinstance(d, dict)
        and d.get('status') in get_args(AccountStatus)
        and ('__Location' not in d or (
            isinstance(d.get('__Location'), str)))
        and ('contact' not in d or (
            isinstance(d['contact'], list)
            and all(isinstance(c, str) for c in d['contact'])))
        and ('termsOfServiceAgreed' not in d or (
            isinstance(d['termsOfServiceAgreed'], bool)))
        and ('orders' not in d or (
            isinstance(d['orders'], str))))


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
