import pytest

from acmeerkat.crypto.openssl import OpenSslCrypto
from acmeerkat import alg_params as ap


@pytest.mark.parametrize('pktext,jsonv', [
    pytest.param("""
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
    }, id='rfc7518_appendixC_Alice'),
    pytest.param("""
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
    }, id='rfc7518_appendixC_Bob'),
    # non-rfc
    pytest.param("""
Private-Key: (2048 bit, 2 primes)
modulus:
    00:d4:ba:fc:27:7c:a1:99:d1:06:ba:29:46:dc:99:
    76:f5:df:32:f2:6e:b7:e4:de:b2:3a:71:e1:e8:10:
    7c:06:5a:34:05:1d:82:a6:a3:f8:f5:b3:99:2e:14:
    5b:02:43:53:01:a9:a9:ad:54:a5:38:be:69:b8:51:
    92:4f:15:85:bb:b0:e7:2d:32:4f:56:24:55:dd:bf:
    9b:c9:4f:08:59:56:c5:d2:a2:b0:c9:4b:8a:aa:ce:
    4e:fc:41:fc:de:a7:d9:1b:45:88:21:ec:e1:7a:44:
    fc:b3:83:69:7b:e1:23:82:d7:5b:07:19:d2:79:af:
    b9:11:af:c7:75:f8:02:88:66:6a:9d:96:17:28:15:
    b9:98:6f:1b:03:c8:df:2d:f7:e9:e9:c2:3b:a8:f8:
    bf:0d:d4:f4:97:ff:ce:fb:9e:a2:77:76:c4:0a:e7:
    9d:da:17:5d:6e:af:01:d0:73:da:1a:96:05:72:d5:
    05:aa:5e:65:1e:a1:87:66:cf:f7:85:21:26:29:59:
    32:18:10:1f:e7:6f:78:c7:77:ce:7a:9a:1b:c7:a4:
    2d:09:15:9f:c1:d7:6b:58:a3:0c:70:2e:5c:9f:f1:
    5f:77:9c:90:f3:bb:43:19:46:c6:d8:a6:85:92:66:
    53:47:b7:ba:5e:5d:6e:0b:78:0e:08:91:dd:d7:b5:
    1c:09
publicExponent: 65537 (0x10001)
privateExponent:
    00:b1:2a:8a:eb:13:1b:3a:70:ed:33:da:7a:e7:b2:
    97:89:78:23:47:39:22:16:27:11:9a:48:ff:00:b4:
    30:51:c5:f9:f6:07:af:e1:91:1b:1f:40:f5:02:88:
    fe:bc:d5:6a:0f:d3:30:c0:ab:33:aa:24:61:58:64:
    2c:18:ff:5e:32:6f:a5:14:95:06:4a:59:0d:91:3c:
    11:09:16:14:8a:dc:8a:bc:31:23:b8:79:cd:1a:a7:
    2f:c3:4c:29:ff:9d:3b:30:26:3f:12:c1:06:a8:74:
    ff:89:c6:6a:d3:4d:56:85:d0:51:4c:a5:0f:85:db:
    c2:f2:d4:97:74:7b:36:22:b3:b2:eb:91:1c:82:1f:
    b7:c9:8c:0c:f8:35:89:f8:4e:84:f1:3a:ea:1a:d8:
    f5:80:41:6a:ce:4f:fe:cd:62:fd:b6:ed:82:c2:c8:
    73:e8:35:f5:8a:e5:06:3b:d9:86:2b:d0:31:6c:fc:
    58:41:05:01:cf:f1:2e:88:e6:78:8c:79:a4:11:33:
    0b:6e:57:96:fa:77:02:ce:99:d3:4a:c9:7a:ea:26:
    64:c9:2b:06:39:8c:0a:f8:cc:ab:e8:31:a6:a0:66:
    1c:c5:e9:93:f3:7a:a6:9e:ae:05:d7:26:61:4d:60:
    f2:79:7c:aa:97:fa:20:54:ea:d6:bf:c6:34:e1:b0:
    05
prime1:
    00:f7:95:10:91:8e:06:8a:cf:58:48:4a:22:33:d1:
    0f:9a:fa:fd:07:3b:f4:d1:99:31:6a:9f:97:e3:4d:
    4a:f0:15:06:bd:4f:4f:b6:4b:18:f6:10:c6:80:33:
    db:79:1f:9a:68:5a:1d:87:a6:87:ef:8f:f7:9e:dd:
    2f:08:e1:0c:30:ec:6e:45:cb:72:03:ba:11:e7:3e:
    db:aa:41:93:85:3d:68:2a:38:99:99:ab:6d:c4:19:
    e3:a7:48:98:e6:90:09:81:19:0b:cb:be:26:0e:d5:
    ac:42:ca:32:95:a7:08:ed:af:99:6c:8c:47:94:60:
    85:da:d1:39:0d:88:9e:c1:ed
prime2:
    00:db:f6:92:8e:ba:41:29:86:55:23:19:8a:47:eb:
    0b:f2:d7:5c:86:34:ad:d8:d4:bd:35:f1:d4:b1:d2:
    cb:7f:50:1d:d4:33:91:6d:ea:04:2f:eb:48:f6:89:
    69:f8:a9:b3:09:fb:2b:67:8a:6c:55:9e:15:4b:7e:
    b3:83:a0:9e:e2:87:f8:87:a3:fb:05:20:62:17:cb:
    a0:5c:1a:a6:13:f7:3f:ed:ac:3b:5b:eb:7e:ce:57:
    04:bf:90:ca:61:55:0d:9f:bb:ff:d2:c1:80:5b:19:
    fb:ba:78:eb:e5:97:6a:72:db:7c:b3:53:ff:ab:24:
    14:d6:ac:3d:b8:83:dd:ef:0d
exponent1:
    00:ea:05:29:bb:1b:af:4d:67:fd:ff:9e:ab:43:a5:
    5a:05:d9:36:70:af:18:93:42:25:76:ae:51:c8:95:
    d7:be:a5:71:50:61:f6:6b:ce:02:53:1c:ba:34:96:
    4f:de:e6:a3:71:fd:b4:29:f3:9c:4c:32:1e:12:38:
    e9:eb:8f:a5:91:5c:fa:42:d8:b1:f5:99:dc:b0:63:
    37:09:70:a0:bb:71:b6:d3:29:da:ee:69:1f:01:1c:
    a3:96:0c:c6:12:31:95:fa:44:2d:65:31:60:11:e7:
    a0:c3:25:12:b9:68:40:c5:42:95:58:08:24:e4:b8:
    73:ed:c8:94:10:19:d2:4e:65
exponent2:
    53:8a:cb:d1:0f:a6:8e:19:ea:1e:01:a6:46:78:5c:
    3a:68:57:48:d5:9b:2d:9e:67:1a:a4:f5:ae:70:2c:
    3f:f7:72:cc:d4:a5:28:84:d8:00:47:31:98:09:4a:
    c9:59:d2:99:38:df:1c:5d:33:96:35:0b:4b:78:1c:
    c0:22:72:16:01:a4:80:07:e4:df:e6:93:bb:0b:e8:
    a4:f2:ae:1f:29:2a:0b:9f:fd:8f:84:da:cd:8d:b9:
    4c:f4:b6:18:cf:8f:f4:1a:18:28:b8:bb:82:5e:55:
    00:56:ca:e9:91:5f:a9:ad:f9:27:b7:00:84:c4:98:
    71:8c:4b:88:d7:f4:a3:c5
coefficient:
    4a:a8:90:d7:e3:6b:85:17:51:4f:f9:74:b9:52:42:
    12:8a:68:98:a5:b2:4c:7b:92:7b:81:0c:e2:82:c5:
    75:67:3e:ff:87:75:16:83:03:3f:93:62:5f:98:6e:
    5b:41:1d:17:1d:8f:18:16:ba:56:0a:3c:37:27:6b:
    13:32:d8:3c:9c:22:fd:45:f5:46:0c:59:4f:22:a0:
    fc:51:b2:40:67:55:3d:14:08:18:17:57:3f:8c:26:
    f8:5a:41:05:d2:76:11:39:71:fe:8d:79:d6:f2:7d:
    6d:82:fb:4f:63:ac:ed:59:8e:77:08:2d:30:37:45:
    37:b9:b5:33:21:91:5d:0c
PSS parameter restrictions:
  Hash Algorithm: SHA2-256
  Mask Algorithm: MGF1 with SHA2-256
  Minimum Salt Length: 32
  Trailer Field: 0x1 (default)
""", {
        'kty': 'RSA',
        'e': 'AQAB',
        'n': (
            'ANS6_Cd8oZnRBropRtyZdvXfMvJut-Tesjpx4egQfAZaNAUdgqaj-PWzmS4UWwJDU'
            'wGpqa1UpTi-abhRkk8Vhbuw5y0yT1YkVd2_m8lPCFlWxdKisMlLiqrOTvxB_N6n2R'
            'tFiCHs4XpE_LODaXvhI4LXWwcZ0nmvuRGvx3X4Aohmap2WFygVuZhvGwPI3y336en'
            'CO6j4vw3U9Jf_zvueond2xArnndoXXW6vAdBz2hqWBXLVBapeZR6hh2bP94UhJilZ'
            'MhgQH-dveMd3znqaG8ekLQkVn8HXa1ijDHAuXJ_xX3eckPO7QxlGxtimhZJmU0e3u'
            'l5dbgt4DgiR3de1HAk'),
    }, id='non-hex_pss_params'),
])
def test_parse_pubkey(pktext, jsonv):
    assert OpenSslCrypto._parse_pubkey(pktext).to_json() == jsonv


def _fit_bits(n: int, step: int) -> int:
    if (mod := n % step) == 0:
        return n
    return n - mod + step


@pytest.mark.parametrize('alg_params,jws_alg,sigsize', [
    (ap.Ec256(), 'ES256', 256 * 2),
    (ap.Ec384(), 'ES384', 384 * 2),
    (ap.Ec512(), 'ES512', _fit_bits(521, 8) * 2),

    (ap.Rsa256(bits=1024), 'RS256', 1024),
    (ap.Rsa256(bits=2048), 'RS256', 2048),
    (ap.Rsa256(bits=4096), 'RS256', 4096),

    (ap.Rsa512(bits=2048), 'RS512', 2048),

    (ap.RsaPss256(bits=2048), 'PS256', 2048),
    (ap.RsaPss384(bits=2048), 'PS384', 2048),
    (ap.RsaPss512(bits=2048), 'PS512', 2048),
    (ap.RsaPss512(bits=4096), 'PS512', 4096),

    (ap.Ed25519(), 'EdDSA', 512),
    (ap.Ed448(), 'EdDSA', 912),
])
def test_gen_check_sign(alg_params, jws_alg, sigsize):
    assert alg_params.get_jws_alg() == jws_alg
    c = OpenSslCrypto(debug=False)
    kp = c.generate_key_pair(alg_params)
    assert len(kp) > 0
    assert c.check_key_pair(kp) is True
    sgn = c.sign(alg_params, kp, b'hello world')
    assert len(sgn) * 8 == sigsize
    csr = c.generate_csr(alg_params, kp, ['example.org'])
    assert len(csr) > 0


def test_check_empty_bytes():
    c = OpenSslCrypto()
    assert c.check_key_pair(b'') is False


def test_rsa_signature_hashes():
    c = OpenSslCrypto()
    # NOTE: hacky, same RSA key may be used with different hashes
    kp = c.generate_key_pair(ap.Rsa256())
    text = b'hello world'
    sgn_256 = c.sign(ap.Rsa256(), kp, text)
    sgn_256_2 = c.sign(ap.Rsa256(), kp, text)
    sgn_512 = c.sign(ap.Rsa512(), kp, text)
    sgn_512_2 = c.sign(ap.Rsa512(), kp, text)
    assert sgn_256 != sgn_512
    assert sgn_256 == sgn_256_2
    assert sgn_512 == sgn_512_2


def test_rsa_modes():
    c = OpenSslCrypto()
    # NOTE: hacky, same RSA key may be used for PSS
    kp = c.generate_key_pair(ap.Rsa256())
    text = b'hello world'
    sgn_reg = c.sign(ap.Rsa256(), kp, text)
    sgn_reg2 = c.sign(ap.Rsa256(), kp, text)
    sgn_pss = c.sign(ap.RsaPss256(), kp, text)
    sgn_pss2 = c.sign(ap.RsaPss256(), kp, text)
    assert sgn_reg != sgn_pss
    assert sgn_reg == sgn_reg2
    # NOTE: PSS is not repeatable
    # that's the whole purpose of PSS
    assert sgn_pss != sgn_pss2
