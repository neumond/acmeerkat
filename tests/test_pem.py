import pytest

from acmeerkat import pem
from acmeerkat import alg_params as ap


def dummy_pem(tag, body):
    return (
        b'-----BEGIN ' + tag + b'-----\n'
        + body + b'\n'
        + b'-----END ' + tag + b'-----')


@pytest.mark.parametrize('bundle,items', [
    (b'', []),
    (b'''
Some text outside
-----BEGIN ABC-----
Abc
-----END ABC-----
and there -----
''', [
        (b'ABC', b'\nAbc\n'),
    ]),
    (b'-----', []),
    (b'-----BEGIN', []),
    (b'-----BEGIN ABC-----', []),
    (b'''
-----BEGIN ABC-----
111
-----BEGIN XYZ-----
222
-----END HJK-----
333
-----END XYZ-----
''', []),
    (b'''
1
-----BEGIN A-----aaa-----END A-----
2
-----BEGIN B-----bbb-----END B-----
3
-----BEGIN C-----ccc-----END C-----
4
''', [
        (b'A', b'aaa'),
        (b'B', b'bbb'),
        (b'C', b'ccc'),
    ]),
    (dummy_pem(b'A1', b'a1'), [(b'A1', b'\na1\n')]),
    (
        b'\n\n'.join([
            dummy_pem(b'A1', b'a1'),
            dummy_pem(b'B2', b'b2'),
        ]),
        [
            (b'A1', b'\na1\n'),
            (b'B2', b'\nb2\n'),
        ]),
])
def test_split_pem_concat(bundle, items):
    assert list(pem.split_pem_concat(bundle)) == [
        (
            b'-----BEGIN ' + typ + b'-----'
            + content
            + b'-----END ' + typ + b'-----')
        for typ, content in items]


@pytest.mark.parametrize('pemobj,result', [
    (b'-----BEGIN X-----12345-----END X-----', (b'X', b'12345')),
    (b'''
-----BEGIN OBJECT-----
something there
-----END OBJECT-----
''', (b'OBJECT', b'\nsomething there\n')),
    (dummy_pem(b'X8', b'x88'), (b'X8', b'\nx88\n')),
])
def test_pem_object_split(pemobj, result):
    assert pem.pem_object_parse(pemobj) == result


@pytest.mark.parametrize('alg_params', [
    ap.Ec256(),
    ap.Ec384(),
    ap.Ec512(),
    ap.Ed25519(),
    ap.Ed448(),
    ap.Rsa256(),
    ap.Rsa256(bits=4096, primes=3, pubexp=3),
])
def test_alg_params_serialize(alg_params):
    b = alg_params.to_bytes()
    assert isinstance(b, bytes)
    alg_params2 = ap.BaseAlgParams.from_bytes(b)
    assert alg_params2 == alg_params


@pytest.mark.parametrize('cb', [
    pem.CertBundle(
        prev=b'293',
        alg_params=ap.Ec384(),
        profile=None,
        private_key=dummy_pem(b'PRIVATE KEY', b'01'),
        cert_chain=(
            dummy_pem(b'CERTIFICATE', b'10'),
            dummy_pem(b'CERTIFICATE', b'11'),
            dummy_pem(b'CERTIFICATE', b'12')),
    ),
])
def test_cert_bundle_serialize(cb):
    cb2 = pem.CertBundle._unpack(cb._pack())
    assert cb == cb2
