import urllib.parse
from collections import abc


__all__ = (
    'split_pem_bundle',
    'pem_object_split',
    'cert_chain_to_firefox_link',
)


_PEM_DASH = b'-----'
_PEM_BEGIN = _PEM_DASH + b'BEGIN '
_PEM_END = _PEM_DASH + b'END '


def split_pem_bundle(pem_bundle: bytes) -> abc.Iterator[bytes]:
    pos = 0
    while True:
        if (pos := pem_bundle.find(_PEM_BEGIN, pos)) < 0:
            return
        obj_start = pos
        if (tpos := pem_bundle.find(_PEM_DASH, pos + len(_PEM_BEGIN))) < 0:
            return
        begin_tag = pem_bundle[pos:tpos + len(_PEM_DASH)]
        end_tag = _PEM_END + begin_tag.removeprefix(_PEM_BEGIN)
        if (pos := pem_bundle.find(end_tag, pos)) < 0:
            return
        yield pem_bundle[obj_start:pos + len(end_tag)]


def pem_object_split(pem_object: bytes) -> tuple[bytes, bytes]:
    # (tag, content)
    pos = pem_object.find(_PEM_BEGIN)
    tagpos = pos + len(_PEM_BEGIN)
    if (pos := pem_object.find(_PEM_DASH, pos + len(_PEM_BEGIN))) < 0:
        raise ValueError
    tag = pem_object[tagpos:pos]
    pos += len(_PEM_DASH)
    if (end_pos := pem_object.rfind(_PEM_END)) < 0:
        raise ValueError
    return tag, pem_object[pos:end_pos]


def cert_chain_to_firefox_link(pem_bundle: bytes) -> str:
    certs = []
    for pem_object in split_pem_bundle(pem_bundle):
        tag, content = pem_object_split(pem_object)
        if tag != b'CERTIFICATE':
            continue  # skip private keys
        certs.append('cert=' + urllib.parse.quote_from_bytes(
            content.replace(b'\n', b'').replace(b' ', b''), safe=''))
    return 'about:certificate?' + '&'.join(certs)
