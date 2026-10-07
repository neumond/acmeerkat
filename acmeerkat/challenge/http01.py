from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from acmeerkat import BaseTokenChallenge


__all__ = (
    'BaseHttp01',
    'DictHttp01',
    'FileHttp01',
    'ManualHttp01',
)


class BaseHttp01(BaseTokenChallenge):
    TYPE: ClassVar[str] = 'http-01'


class ManualHttp01(BaseHttp01):
    def chal_set(self, name: str, content: str) -> None:
        print('Put challenge:')
        print(f'    File name: {name}')
        print(f'      Content: {content}')
        print('Press enter when ready')
        input()

    def chal_remove(self, name: str) -> None:
        print(f'Remove challenge file: {name}')
        print('Press enter when ready')
        input()


@dataclass
class DictHttp01(BaseHttp01):
    d: dict[str, str]

    def chal_set(self, name: str, content: str) -> None:
        self.d[name] = content

    def chal_remove(self, name: str) -> None:
        self.d.pop(name, None)


@dataclass
class FileHttp01(BaseHttp01):
    directory: Path

    def _check_name(self, name: str) -> None:
        assert '/' not in name
        assert '..' not in name

    def chal_set(self, name: str, content: str) -> None:
        self._check_name(name)
        (self.directory / name).write_text(content)

    def chal_remove(self, name: str) -> None:
        self._check_name(name)
        (self.directory / name).unlink(missing_ok=True)
