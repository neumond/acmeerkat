import pytest

from acmeerkat.core import jws_serialize, jwk_thumbprint


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
    assert jws_serialize(input, separators=(',\r\n ', ':')) == encoded


def test_jwk_thumbprint():
    # rfc7638 example
    assert jwk_thumbprint({
        'kty': 'RSA',
        'n': (
            '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt'
            'VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6'
            '4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD'
            'W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9'
            '1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH'
            'aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw'
        ),
        'e': 'AQAB',
        'alg': 'RS256',
        'kid': '2011-04-29',
    }) == 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'
