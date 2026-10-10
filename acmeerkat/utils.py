import base64
import json
import re
from collections import abc
from random import random
from time import sleep
from typing import Any


__all__ = (
    'b64_jose',
    'bin_json_dumps',
    'is_valid_domain',
    'jws_serialize',
    'periodic',
    'uint_to_bytes',
)


COMPACT_JSON_SEP = (',', ':')


def b64_jose(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')


def bin_json_dumps(
    d: dict[Any, Any],
    separators: tuple[str, str] = COMPACT_JSON_SEP,
) -> bytes:
    return json.dumps(d, separators=separators).encode('utf-8')


def jws_serialize(
    d: dict[Any, Any],
    separators: tuple[str, str] = COMPACT_JSON_SEP,
) -> str:
    return b64_jose(bin_json_dumps(d, separators=separators))


def uint_to_bytes(n: int) -> bytes:
    if n == 0:
        return b'\x00'
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big', signed=False)


_LABEL_RPART = (
    r'(?!-)'  # Must not start with hyphen
    r'[a-z0-9-]{1,63}'
    r'(?<!-)'  # Must not end with hyphen
)
_DOMAIN_RE = re.compile(
    r'^'
    r'(?=.{1,253}$)'  # Total length ≤ 253
    r'(?:\*\.)?'  # optional wildcard
    rf'(?:{_LABEL_RPART}\.)+'
    rf'({_LABEL_RPART})'  # TLD
    r'$')


def is_valid_domain(d: str) -> bool:
    return _DOMAIN_RE.match(d) is not None


def periodic(
    period: float,
    jitter: float = 0.,
) -> abc.Iterator[None]:
    half_jitter = jitter * 0.5
    while True:
        yield
        sleep(period + random() * jitter - half_jitter)
