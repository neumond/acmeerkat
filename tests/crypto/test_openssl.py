import pytest

from acmeerkat import Algorithm
from acmeerkat.crypto.openssl import OpenSSLCrypto


# rfc7518 appendix C
@pytest.mark.parametrize('pktext,jsonv', [
    # Alice
    ("""
Private-Key: (256 bit)
priv:
    d3:f3:71:69:13:d4:31:0a:00:26:de:74:1b:3f:18:
    89:3a:fc:81:14:f0:c8:46:82:ba:67:7e:31:3a:13:
    98:8a
pub:
    04:80:8d:06:00:82:c1:76:ee:d3:e7:76:a4:ac:59:
    8c:c8:67:2c:17:79:f9:74:ee:cc:9b:03:41:1c:a5:
    b9:49:5d:48:b5:bf:c5:27:df:ce:53:d6:ac:71:15:
    23:7d:03:1c:cf:f8:7a:05:70:b7:73:50:a9:e5:03:
    ee:73:05:a6:9b
ASN1 OID: prime256v1
NIST CURVE: P-256
""", {
        'kty': 'EC',
        'crv': 'P-256',
        'x': 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
        'y': 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
        # 'd': '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
    }),
    # Bob
    ("""
Private-Key: (256 bit)
priv:
    54:49:83:66:90:d7:5c:af:29:f0:dd:02:9d:db:31:
    b3:dd:b8:ab:a9:d2:d5:15:c5:01:24:65:e8:17:d4:
    a9:dc
pub:
    04:c1:e3:49:cb:61:ec:70:24:8c:e8:01:03:4c:38:
    34:e1:b8:8e:be:11:61:cb:25:af:38:74:1f:78:5f:
    cf:c4:c4:7b:c9:67:08:ef:80:95:2b:53:f8:d2:55:
    5f:e7:2b:84:1e:d0:45:88:62:8b:1d:37:8a:59:49:
    39:50:0e:c9:c9
ASN1 OID: prime256v1
NIST CURVE: P-256
""", {
        'kty': 'EC',
        'crv': 'P-256',
        'x': 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
        'y': 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        # 'd': 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
    }),
])
def test_parse_pubkey(pktext, jsonv):
    assert OpenSSLCrypto._parse_pubkey(pktext) == jsonv


def test_gen_and_check():
    c = OpenSSLCrypto()
    kp = c.generate_key_pair(Algorithm.ES256)
    assert c.check_key_pair(kp) is True
    assert c.check_key_pair(b'') is False
