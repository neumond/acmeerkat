from base64 import urlsafe_b64decode

import pytest

from acmeerkat import jwk, utils


# examples from rfc7515
@pytest.mark.parametrize('input,encoded', [
    ({
        'typ': 'JWT',
        'alg': 'HS256',
    }, 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'),
    ({
        'iss': 'joe',
        'exp': 1300819380,
        'http://example.com/is_root': True,
    }, (
        'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlL'
        'mNvbS9pc19yb290Ijp0cnVlfQ')),
    ({'alg': 'ES256'}, 'eyJhbGciOiJFUzI1NiJ9'),
])
def test_jws_serialize(input, encoded):
    assert utils.jws_serialize(input, separators=(',\r\n ', ':')) == encoded


def test_jwk_thumbprint():
    # rfc7638 example
    k = jwk.RsaJsonWebPubKey(
        n=urlsafe_b64decode(
            b'0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt'
            b'VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6'
            b'4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD'
            b'W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9'
            b'1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH'
            b'aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw=='),
        e=65537)
    assert k.thumbprint() == 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'


@pytest.mark.parametrize('n,b', [
    (0, b'\x00'),
    (1, b'\x01'),
    (0xFF, b'\xFF'),
    (0x0100, b'\x01\x00'),
    (0xFFFF, b'\xFF\xFF'),
    (0x010203, b'\x01\x02\x03'),
    (0x01_0002_0003, b'\x01\x00\x02\x00\x03'),
])
def test_uint_to_bytes(n, b):
    assert utils.uint_to_bytes(n) == b
    assert int.from_bytes(b, byteorder='big', signed=False) == n
