import fcntl
import os
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from acmeerkat import BaseKVStorage


__all__ = ('FilePairKVStorage', )


@dataclass
class FilePairKVStorage(BaseKVStorage):
    """
    Appends to file1,
    then compacts to file2, then appends to file2,
    then compacts to file1, then appends to file1, etc.

    This allows durable storage and mounting both files directly,
    without relying on file renaming.

    Record types:
    1 - regular kv pair (ksize:4, vsize:4, k:var, v:var)
    2 - key deleted (ksize:4, k:var)
    3 - compaction done ()
    """
    file1: Path
    file2: Path
    compact_threshold: int = 30  # compact if 30% can be stripped
    no_compact_size: int = 65_536

    _data: dict[bytes, bytes] = field(init=False)
    _active: int = field(init=False)
    _version: int = field(init=False)
    _total_size: int = field(init=False)
    _compactible_size: int = field(init=False)

    def _should_compact(self) -> bool:
        if self._total_size < self.no_compact_size:
            return False  # don't bother for small files
        perc = self._compactable_size * 100 // self._total_size
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

    @staticmethod
    def _read_file(p: Path) -> tuple[int, int, int, dict[bytes, bytes]]:
        version = -1
        total_size = 0
        compactable_size = 0
        cap_found = False
        kv: dict[bytes, bytes] = {}
        try:
            with p.open('rb') as f:
                def read_exactly(ln: int) -> bytes:
                    nonlocal total_size
                    if len(b := f.read(ln)) != ln:
                        raise ValueError
                    total_size += ln
                    return b

                def read_int32() -> int:
                    return int.from_bytes(read_exactly(4))

                version = read_int32()
                while True:
                    match read_int32():
                        case 1:
                            ksize = read_int32()
                            vsize = read_int32()
                            k = read_exactly(ksize)
                            v = read_exactly(vsize)
                            if k in kv:
                                compactable_size += 8 + ksize + len(kv[k])
                            kv[k] = v
                        case 2:
                            ksize = read_int32()
                            k = read_exactly(ksize)
                            if k in kv:
                                compactable_size += 8 + ksize + len(kv[k])
                                compactable_size += 4 + ksize
                            kv.pop(k, None)
                        case 3:
                            cap_found = True
        except (FileNotFoundError, ValueError):
            pass
        """
        Version numbers:
        >=0: normal
        -1: file not found or empty
        -2: file is corrupted
        """
        if version >= 0 and not cap_found:
            # no cap record means interrupted compaction process
            # some records are not written yet
            # we must use previous file
            version = -2
            warnings.warn(f'KV file {p} is corrupted')
        return (
            version,
            total_size,
            compactable_size,
            kv)

    def _active_inactive_paths(self) -> tuple[Path, Path]:
        match self._active:
            case 1:
                return self.file1, self.file2
            case 2:
                return self.file2, self.file1
        raise ValueError

    def __post_init__(self) -> None:
        v1, tot1, comp1, d1 = self._read_file(self.file1)
        v2, tot2, comp2, d2 = self._read_file(self.file2)

        if v1 == -2 and v2 == -2:  # must not happen even after power outages
            raise Exception(
                "Both KV files are corrupted, "
                "you probably need to inspect what's left")

        if v1 >= 0 and v1 == v2:
            raise Exception(
                "Both KV files have same version, "
                "most likely both are corrupted")

        elif v1 < 0 and v2 < 0:  # both unsuitable, switch to first
            self._active, self._data, self._version = 1, {}, 0
            self._total_size, self._compactable_size = 8, 0
            act_path, inact_path = self._active_inactive_paths()
            act_path.write_bytes(
                self._version.to_bytes(4)
                + (3).to_bytes(4))  # cap record
            # make empty second file just in case
            # to fire possible permission errors on first start
            inact_path.write_bytes(b'')

        else:  # at least one is fine
            self._active = self._version_fight(v1, v2)
            (
                self._version, self._total_size,
                self._compactable_size, self._data,
            ) = {
                1: (v1, tot1, comp1, d1),
                2: (v2, tot2, comp2, d2),
            }[self._active]

    def compact(self) -> None:
        self._active = {1: 2, 2: 1}[self._active]
        self._version = (self._version + 1) % 0x1_0000_0000
        act_path, inact_path = self._active_inactive_paths()
        with act_path.open('wb') as f:
            fcntl.lockf(f, fcntl.LOCK_EX)
            f.write(self._version.to_bytes(4))
            for k, v in self._data.items():
                f.write((1).to_bytes(4))  # kv record
                f.write(len(k).to_bytes(4))
                f.write(len(v).to_bytes(4))
                f.write(k)
                f.write(v)
            f.write((3).to_bytes(4))  # cap record
            self._total_size = f.tell()
            self._compactable_size = 0
            f.flush()
            os.fsync(f.fileno())
        inact_path.write_bytes(b'')

    def update(self, u: dict[bytes, bytes]) -> None:
        act_path, _ = self._active_inactive_paths()
        with act_path.open('ab') as f:
            fcntl.lockf(f, fcntl.LOCK_EX)
            for k, v in u.items():
                if v:
                    self._data[k] = v
                    f.write((1).to_bytes(4))  # kv record
                    f.write(len(k).to_bytes(4))
                    f.write(len(v).to_bytes(4))
                    f.write(k)
                    f.write(v)
                else:
                    self._data.pop(k, None)
                    f.write((2).to_bytes(4))  # key delete record
                    f.write(len(k).to_bytes(4))
                    f.write(k)
            f.flush()
            os.fsync(f.fileno())

        if self._should_compact():
            self.compact()

    def get(self, k: bytes) -> bytes:
        return self._data.get(k, b'')
