import base64
import json


COMPACT_JSON_SEP = (',', ':')


def b64_jose(b):
    return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')


def bin_json_dumps(d: dict, separators=COMPACT_JSON_SEP) -> bytes:
    return json.dumps(d, separators=separators).encode('utf-8')


def jws_serialize(d: dict, separators=COMPACT_JSON_SEP) -> str:
    return b64_jose(bin_json_dumps(d, separators=separators))


def uint_to_bytes(n: int) -> bytes:
    if n == 0:
        return b'\x00'
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big', signed=False)
