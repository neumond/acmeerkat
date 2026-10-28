import base64
import json
import re
from collections import abc
from datetime import datetime, timezone
from random import random
from time import sleep
from typing import Any


__all__ = (
    'b64_jose',
    'bin_json_dumps',
    'bin_json_loads',
    'bin_optstr_dump',
    'bin_optstr_load',
    'bin_str_dump',
    'bin_str_load',
    'is_valid_domain',
    'jws_serialize',
    'periodic',
    'uint_to_bytes',
    'utc_now',
)


COMPACT_JSON_SEP = (',', ':')


def b64_jose(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')


def bin_json_dumps(
    d: Any,
    separators: tuple[str, str] = COMPACT_JSON_SEP,
) -> bytes:
    return json.dumps(d, separators=separators).encode('utf-8')


def bin_json_loads(j: bytes) -> Any:
    return json.loads(j.decode('utf-8'))


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


def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def bin_isoformat(d: datetime) -> bytes:
    if d.tzinfo is not timezone.utc:
        raise ValueError('UTC timezone required')
    iso = d.isoformat().rsplit('+', 1)[0] + 'Z'
    return iso.encode('ascii')


def bin_fromisoformat(b: bytes) -> datetime:
    return datetime.fromisoformat(b.decode('ascii'))


def bin_str_dump(s: str) -> bytes:
    return s.encode('utf-8')


def bin_str_load(b: bytes) -> str:
    return b.decode('utf-8')


def bin_optstr_dump(s: str | None) -> bytes:
    return b'' if s is None else s.encode('utf-8')


def bin_optstr_load(b: bytes) -> str | None:
    return None if not b else b.decode('utf-8')
