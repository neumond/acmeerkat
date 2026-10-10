import random
import tempfile
from pathlib import Path

import pytest

from acmeerkat.storage.file_pair import FilePairKVStorage, BadMagicError


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


@pytest.fixture
def file_pair(tempdir):
    return tempdir / '1.bin', tempdir / '2.bin'


@pytest.mark.parametrize('transactions,max_tx_acts', [
    (0, 5),
    (1, 1),
    (1, 5),
    (10, 8),
    (100, 8),
    (1000, 8),
])
def test_storage(file_pair, transactions, max_tx_acts):
    s = FilePairKVStorage(*file_pair)
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

    s2 = FilePairKVStorage(*file_pair)
    assert s2._data == expected
    for k, v in expected.items():
        s2.get(k) == v


def test_broken_transaction(file_pair):
    s = FilePairKVStorage(*file_pair)
    assert s._active == 1
    s.update({b'valid': b'1', b'validB': b'1B'})
    assert s._active == 1
    s.update({b'broken': b'2', b'brokenB': b'2B'})
    assert s._active == 1
    del s

    with file_pair[0].open('rb+') as f:
        content = f.read(1000)
        f.seek(len(content) - 5)
        f.truncate()

    s = FilePairKVStorage(*file_pair)
    assert s.get(b'valid') == b'1'
    assert s.get(b'validB') == b'1B'
    assert s.get(b'broken') == b''  # not exists
    assert s.get(b'brokenB') == b''
    s.update({b'another': b'3', b'anotherB': b'3B'})
    del s

    s = FilePairKVStorage(*file_pair)
    assert s.get(b'valid') == b'1'
    assert s.get(b'validB') == b'1B'
    assert s.get(b'broken') == b''  # not exists
    assert s.get(b'brokenB') == b''
    assert s.get(b'another') == b'3'
    assert s.get(b'anotherB') == b'3B'
    # broken file tail didn't break incoming new transactions


def test_broken_compaction(file_pair):
    s = FilePairKVStorage(*file_pair)
    assert s._active == 1
    s.update({b'a': b'1', b'b': b'2', b'c': b'3'})
    assert s._active == 1
    s.compact(clean_2nd_file=False)
    assert s._active == 2
    del s

    with file_pair[1].open('rb+') as f:
        content = f.read(1000)
        f.seek(len(content) - 7)
        f.truncate()

    s = FilePairKVStorage(*file_pair)
    # rollback to file 1
    assert s._active == 1
    assert s.get(b'a') == b'1'
    assert s.get(b'b') == b'2'
    assert s.get(b'c') == b'3'


def test_no_unknown_file_overwrite(file_pair):
    # NOTE: very small files (<12b) get overwritten
    content = b'some text file here'
    file_pair[0].write_bytes(content)

    with pytest.raises(BadMagicError):
        FilePairKVStorage(*file_pair)

    assert file_pair[0].read_bytes() == content
