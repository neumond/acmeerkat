import urllib.parse
from collections import abc
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, ClassVar, Self

from . import x509
from .alg_params import BaseAlgParams
from .types import PemObject, PemConcat, PemTag, PemBase64Body


__all__ = (
    'CertBundle',
    'pem_object_parse',
    'split_pem_concat',
)


_PEM_DASH = b'-----'
_PEM_BEGIN = _PEM_DASH + b'BEGIN '
_PEM_END = _PEM_DASH + b'END '


def split_pem_concat(concat: PemConcat) -> abc.Iterator[PemObject]:
    # TODO: memoryview in result
    pos = 0
    while True:
        if (pos := concat.find(_PEM_BEGIN, pos)) < 0:
            return
        obj_start = pos
        if (tpos := concat.find(
            _PEM_DASH, pos + len(_PEM_BEGIN)
        )) < 0:
            return
        begin_tag = concat[pos:tpos + len(_PEM_DASH)]
        end_tag = _PEM_END + begin_tag.removeprefix(_PEM_BEGIN)
        if (pos := concat.find(end_tag, pos)) < 0:
            return
        yield concat[obj_start:pos + len(end_tag)]


def pem_object_parse(pem_object: PemObject) -> tuple[PemTag, PemBase64Body]:
    "Return (tag, base64_body) of a PEM-encoded object"
    # TODO: memoryview in result
    pos = pem_object.find(_PEM_BEGIN)
    tagpos = pos + len(_PEM_BEGIN)
    if (pos := pem_object.find(_PEM_DASH, pos + len(_PEM_BEGIN))) < 0:
        raise ValueError
    tag = pem_object[tagpos:pos]
    pos += len(_PEM_DASH)
    if (end_pos := pem_object.rfind(_PEM_END)) < 0:
        raise ValueError
    return tag, pem_object[pos:end_pos]


def _write_into(
    data: bytes,
    target: Path | str | bytearray | BinaryIO,
) -> None:
    match target:
        case Path():
            target.write_bytes(data)
        case str():
            Path(target).write_bytes(data)
        case bytearray():
            target.extend(data)
        case _:
            target.write(data)


@dataclass(frozen=True)
class CertBundle:
    prev: bytes
    alg_params: BaseAlgParams
    profile: str | None
    private_key: PemObject
    cert_chain: tuple[PemObject, ...]

    def get_firefox_link(self) -> str:
        "View cert chain in firefox"
        cqs = []
        for cert in self.cert_chain:
            cqs.append('cert=' + urllib.parse.quote_from_bytes(
                cert.replace(b'\n', b'').replace(b' ', b''), safe=''))
        return 'about:certificate?' + '&'.join(cqs)

    def get_leaf_cert_info(self) -> x509.CertInfo:
        for cert in self.cert_chain:
            cinfo = x509.parse_cert(cert)
            if cinfo.is_leaf:
                return cinfo
        raise ValueError('No leaf certificate found in bundle')

    def write_nginx_files(
        self,
        cert_chain: Path | str | bytearray | BinaryIO,
        private_key: Path | str,
    ) -> None:
        _write_into(
            b'\n\n'.join(self.cert_chain),
            cert_chain)
        _write_into(self.private_key, private_key)

    def write_haproxy_file(
        self,
        bundle: Path | str | bytearray | BinaryIO,
    ) -> None:
        _write_into(
            b'\n\n'.join(self.cert_chain + (self.private_key, )),
            bundle)

    _PACK_VERSION: ClassVar[int] = 1

    def _pack(self) -> bytes:
        chunks = [
            self.prev,
            self.profile.encode('utf-8') if self.profile else b'',
            self.alg_params.to_bytes(),
            self.private_key,
            *self.cert_chain]
        out = []
        out.append(self._PACK_VERSION.to_bytes(4))
        out.append(len(chunks).to_bytes(4))
        out.extend(len(c).to_bytes(4) for c in chunks)
        out.extend(chunks)
        return b''.join(out)

    @classmethod
    def _unpack(cls, b: bytes) -> Self:
        pver = int.from_bytes(b[0:4])
        if pver != cls._PACK_VERSION:
            raise ValueError('Bad format version')
        nchunks = int.from_bytes(b[4:8])
        clens = [
            int.from_bytes(b[pos + 8:pos + 12])
            for pos in range(0, 4 * nchunks, 4)]
        pos = 4 * (nchunks + 2)
        out = []
        for ln in clens:
            out.append(b[pos:pos + ln])
            pos += ln
        return cls(
            prev=out[0],
            profile=out[1].decode('utf-8') if out[1] else None,
            alg_params=BaseAlgParams.from_bytes(out[2]),
            private_key=out[3],
            cert_chain=tuple(out[4:]))
