import fcntl
import os
from dataclasses import dataclass, field, InitVar
from enum import IntEnum
from pathlib import Path
from typing import BinaryIO, Self

from acmeerkat import BaseKVStorage


__all__ = ('FilePairKVStorage', 'BadMagicError')


# TODO: breaks when used in different processes at the same time


class RecordTag(IntEnum):
    pair = 1  # (ksize:4, vsize:4, k:var, v:var)
    deleted = 2  # (ksize:4, k:var)
    commit = 3  # (), transaction finished


class EndOfFile(Exception):
    "valid end of file"


class IncompleteReadError(Exception):
    pass


class BadMagicError(Exception):
    pass


_MAGIC_BYTES = b'ACMEERKAT001'


@dataclass
class JustReadFile:
    empty: bool = False
    has_transaction: bool = False
    broken_tail: bool = True
    version: int = -1
    total_size: int = 0
    compactible_size: int = 0
    kv: dict[bytes, bytes] = field(default_factory=dict)

    @property
    def has_some_data(self) -> bool:
        return (
            not self.empty
            and self.has_transaction)

    def _read_data(self, f: BinaryIO) -> None:
        def read_exactly(ln: int, eof_on_zero: bool = False) -> bytes:
            if len(b := f.read(ln)) != ln:
                if len(b) == 0 and eof_on_zero:
                    raise EndOfFile
                raise IncompleteReadError
            self.total_size += ln
            return b

        def read_int32(eof_on_zero: bool = False) -> int:
            return int.from_bytes(read_exactly(4, eof_on_zero))

        try:
            magic = read_exactly(12, eof_on_zero=True)
        except EndOfFile:
            raise FileNotFoundError  # same as empty file
        if magic != _MAGIC_BYTES:
            raise BadMagicError

        self.version = read_int32()

        transaction: dict[bytes, bytes] = {}

        def on_rewrite_key(k: bytes) -> None:
            if (rv := transaction.get(k, None)) is not None:
                if rv != b'':  # tombstone already in .compactible_size
                    # rewrites same key in transaction
                    self.compactible_size += 8 + len(k) + len(rv)
            elif (rv := self.kv.get(k)):
                # rewrites record outside the transaction
                self.compactible_size += 8 + len(k) + len(rv)

        while True:
            match RecordTag(read_int32(eof_on_zero=not transaction)):
                case RecordTag.pair:
                    ksize = read_int32()
                    vsize = read_int32()
                    k = read_exactly(ksize)
                    v = read_exactly(vsize)
                    on_rewrite_key(k)
                    transaction[k] = v
                case RecordTag.deleted:
                    ksize = read_int32()
                    k = read_exactly(ksize)
                    on_rewrite_key(k)
                    self.compactible_size += 4 + ksize
                    transaction[k] = b''
                case RecordTag.commit:
                    self.has_transaction = True
                    for k, v in transaction.items():
                        if v:
                            self.kv[k] = v
                        else:
                            self.kv.pop(k, None)
                    transaction.clear()

    @classmethod
    def read(cls, p: Path) -> Self:
        self = cls()
        try:
            with p.open('rb') as f:
                self._read_data(f)
        except FileNotFoundError:
            self.empty = True
            self.broken_tail = False
        except EndOfFile:
            self.broken_tail = False
        except IncompleteReadError:
            pass
        return self

    @classmethod
    def write_fresh_file(cls, p: Path) -> Self:
        self = cls()
        self.empty = False
        self.has_transaction = True
        self.broken_tail = False
        self.version = 1
        with p.open('wb') as f:
            f.write(_MAGIC_BYTES)
            f.write(self.version.to_bytes(4))
            # empty commit distinguishes from broken compaction
            f.write(RecordTag.commit.to_bytes(4))
            self.total_size = f.tell()
        return self


@dataclass
class FilePairKVStorage(BaseKVStorage):
    """
    Appends to file1,
    then compacts to file2, then appends to file2,
    then compacts to file1, then appends to file1, etc.

    This allows durable storage and mounting both files directly,
    without relying on file renaming.
    """
    file1: InitVar[Path | str]
    file2: InitVar[Path | str]
    compact_threshold: int = 30  # compact if 30% can be stripped
    no_compact_size: int = 65_536

    _file1: Path = field(init=False)
    _file2: Path = field(init=False)
    _data: dict[bytes, bytes] = field(init=False)
    _active: int = field(init=False)
    _version: int = field(init=False)
    _total_size: int = field(init=False)
    _compactible_size: int = field(init=False)

    def _should_compact(self) -> bool:
        if self._total_size < self.no_compact_size:
            return False  # don't bother for small files
        perc = self._compactible_size * 100 // self._total_size
        return perc >= self.compact_threshold

    @staticmethod
    def _version_fight(v1: int, v2: int) -> int:
        if v1 < 0:
            return 2
        if v2 < 0:
            return 1
        diff = (v2 - v1) % 0x1_0000_0000
        if 0 < diff < 0x8000_0000:
            return 2
        return 1

    def _active_inactive_paths(self) -> tuple[Path, Path]:
        match self._active:
            case 1:
                return self._file1, self._file2
            case 2:
                return self._file2, self._file1
        raise ValueError

    def __post_init__(self, file1: Path | str, file2: Path | str) -> None:
        self._file1 = Path(file1) if isinstance(file1, str) else file1
        self._file2 = Path(file2) if isinstance(file2, str) else file2

        rf1 = JustReadFile.read(self._file1)
        rf2 = JustReadFile.read(self._file2)

        match (rf1.has_some_data, rf2.has_some_data):
            case (False, False):
                rf1 = JustReadFile.write_fresh_file(self._file1)
                self._active = 1
            case (True, False):
                self._active = 1
            case (False, True):
                self._active = 2
            case (True, True):
                self._active = self._version_fight(rf1.version, rf2.version)

        rf_main = {1: rf1, 2: rf2}[self._active]
        self._version = rf_main.version
        self._total_size = rf_main.total_size
        self._compactible_size = rf_main.compactible_size
        self._data = rf_main.kv

        if rf_main.broken_tail:
            # can't append to current file, force-switching
            self.compact()

    def compact(self, clean_2nd_file: bool = True) -> None:
        self._active = {1: 2, 2: 1}[self._active]
        self._version = (self._version + 1) % 0x1_0000_0000
        act_path, inact_path = self._active_inactive_paths()
        with act_path.open('wb') as f:
            fcntl.lockf(f, fcntl.LOCK_EX)
            f.write(_MAGIC_BYTES)
            f.write(self._version.to_bytes(4))
            for k, v in self._data.items():
                f.write(RecordTag.pair.to_bytes(4))
                f.write(len(k).to_bytes(4))
                f.write(len(v).to_bytes(4))
                f.write(k)
                f.write(v)
            f.write(RecordTag.commit.to_bytes(4))
            self._total_size = f.tell()
            self._compactible_size = 0
            f.flush()
            os.fsync(f.fileno())
        if clean_2nd_file:
            inact_path.write_bytes(b'')

    def update(self, u: dict[bytes, bytes]) -> None:
        act_path, _ = self._active_inactive_paths()
        with act_path.open('ab') as f:
            fcntl.lockf(f, fcntl.LOCK_EX)
            for k, v in u.items():
                if v:
                    self._data[k] = v
                    f.write(RecordTag.pair.to_bytes(4))
                    f.write(len(k).to_bytes(4))
                    f.write(len(v).to_bytes(4))
                    f.write(k)
                    f.write(v)
                else:
                    self._data.pop(k, None)
                    f.write(RecordTag.deleted.to_bytes(4))
                    f.write(len(k).to_bytes(4))
                    f.write(k)
            f.write(RecordTag.commit.to_bytes(4))
            f.flush()
            os.fsync(f.fileno())

        if self._should_compact():
            self.compact()

    def get(self, k: bytes) -> bytes:
        return self._data.get(k, b'')
