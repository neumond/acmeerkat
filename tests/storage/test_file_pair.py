import random
import tempfile
from pathlib import Path

import pytest

from acmeerkat.storage.file_pair import FilePairKVStorage


@pytest.mark.parametrize('a,b,r', [
    (-1, 0, 0),
    (-1, 96, 96),
    (-2, 96, 96),
    (1, 2, 2),
    (2, 8, 8),
    (5, 3, 5),
    (0xFFFF_FFFF, 0, 0),
    (0xFFFF_FFFF, 4, 4),
    (0xFFFF_FFFF, 580, 580),
    (0xF000_0000, 580, 580),
    (0xFFFF_FFFF, 0xFFFF_FFFE, 0xFFFF_FFFF),
])
def test_version_fight(a, b, r):
    assert [None, a, b][FilePairKVStorage._version_fight(a, b)] == r
    assert [None, b, a][FilePairKVStorage._version_fight(b, a)] == r


@pytest.fixture
def tempdir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.mark.parametrize('transactions,max_tx_acts', [
    (0, 5),
    (1, 1),
    (1, 5),
    (10, 8),
    (100, 8),
    (1000, 8),
])
def test_storage(tempdir, transactions, max_tx_acts):
    s = FilePairKVStorage(tempdir / '1.bin', tempdir / '2.bin')
    expected = {}
    for _ in range(transactions):
        for _ in range(random.randint(1, max_tx_acts)):
            upd = {}
            if expected and random.random() < 0.1:
                k, _ = expected.popitem()
                upd[k] = b''
            else:
                k = b'k/' + random.randbytes(random.randint(0, 300))
                v = random.randbytes(random.randint(1, 3000))
                expected[k] = v
                upd[k] = v
            s.update(upd)
    assert s._data == expected
    for k, v in expected.items():
        s.get(k) == v
    assert s.get(b'notexist') == b''

    s2 = FilePairKVStorage(tempdir / '1.bin', tempdir / '2.bin')
    assert s2._data == expected
    for k, v in expected.items():
        s2.get(k) == v
