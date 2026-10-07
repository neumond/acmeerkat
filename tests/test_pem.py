import pytest

from acmeerkat.pem import split_pem_bundle, pem_object_split


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
])
def test_split_pem_bundle(bundle, items):
    assert list(split_pem_bundle(bundle)) == [
        (
            b'-----BEGIN ' + typ + b'-----'
            + content
            + b'-----END ' + typ + b'-----')
        for typ, content in items]


@pytest.mark.parametrize('pem,inner', [
    (b'-----BEGIN X-----12345-----END X-----', (b'X', b'12345')),
    (b'''
-----BEGIN OBJECT-----
something there
-----END OBJECT-----
''', (b'OBJECT', b'\nsomething there\n')),
])
def test_pem_object_split(pem, inner):
    assert pem_object_split(pem) == inner
