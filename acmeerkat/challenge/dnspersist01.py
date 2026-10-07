from collections import abc
from contextlib import contextmanager
from dataclasses import dataclass
from typing import ClassVar

from acmeerkat import BaseChallenge, AuthzIdentifier, ChallengeConfig


__all__ = ('DnsPersist01', )


@dataclass
class DnsPersist01(BaseChallenge):
    # all dns persist challenges basically do nothing
    # user sets TXT record manually only once
    TYPE: ClassVar[str] = 'dns-persist-01'
    debug: bool = False

    @contextmanager
    def _perform(
        self,
        identifier: AuthzIdentifier,
        config: ChallengeConfig,
        thumbprint: str,
    ) -> abc.Iterator[None]:
        if self.debug:
            print('DNS Persist 01 challenge:')
            print(identifier)
            print(config)
        yield
