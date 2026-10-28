import base64
from collections import abc
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Self


__all__ = (
    'CertInfo',
    'parse_cert',
)


type ByteBuffer = bytes | bytearray | memoryview


@dataclass(slots=True)
class TlvReader:
    b: ByteBuffer
    off: int = 0

    def peek(self, n: int) -> ByteBuffer:
        return self.b[self.off:self.off + n]

    def read(self, n: int) -> ByteBuffer:
        r = self.b[self.off:self.off + n]
        self.off += len(r)
        return r

    def read_length(self) -> int:
        if (first := self.read(1)[0]) < 0x80:
            return first
        return int.from_bytes(self.read(first & 0x7F), 'big')

    def read_tlv(self, require_tag: int | None = None) -> tuple[int, Self]:
        tag = self.read(1)[0]
        if require_tag is not None and tag != require_tag:
            raise ValueError(f'Bad tag {tag}, expected {require_tag}')
        length = self.read_length()
        return tag, type(self)(self.read(length))

    def iter_sequence_of_tlv(
        self, require_tag: int | None = None,
    ) -> abc.Iterator[tuple[int, Self]]:
        while len(self.peek(1)) > 0:
            yield self.read_tlv(require_tag)

    def reset(self) -> None:
        self.off = 0


def _pem_to_der(pem: bytes) -> bytes:
    return base64.b64decode(
        pem
        .strip(b'\n')
        .removeprefix(b'-----BEGIN CERTIFICATE-----')
        .removesuffix(b'-----END CERTIFICATE-----')
        .replace(b'\n', b''))


def _parse_time(tag: int, value: TlvReader) -> datetime:
    s = bytes(value.b).decode('ascii')
    if tag == 0x17:  # UTCTime: YYMMDDHHMMSSZ
        year = int(s[0:2])
        year += 2000 if year < 50 else 1900  # per spec
        dt = datetime(
            year, int(s[2:4]), int(s[4:6]),
            int(s[6:8]), int(s[8:10]), int(s[10:12]),
            tzinfo=timezone.utc)
    elif tag == 0x18:  # GeneralizedTime: YYYYMMDDHHMMSSZ
        dt = datetime(
            int(s[0:4]), int(s[4:6]), int(s[6:8]),
            int(s[8:10]), int(s[10:12]), int(s[12:14]),
            tzinfo=timezone.utc)
    else:
        raise ValueError(f'Unexpected time tag: {tag:#x}')
    return dt


def _parse_subject_cn(subject: TlvReader) -> str | None:
    for _, rdn in subject.iter_sequence_of_tlv(0x31):
        for _, atv in rdn.iter_sequence_of_tlv(0x30):
            _, oid = atv.read_tlv(0x06)
            if oid.peek(100) == b'\x55\x04\x03':  # 2.5.4.3, commonName
                _, val = atv.read_tlv()
                return bytes(val.b).decode('utf-8')
    return None


def _parse_san(extensions: TlvReader) -> list[str]:
    for _, ext in extensions.iter_sequence_of_tlv(0x30):
        _, oid = ext.read_tlv()
        if oid.peek(100) != b'\x55\x1D\x11':  # 2.5.29.17, subjectAltName
            continue
        if ext.peek(1) == b'\x01':
            ext.read_tlv()  # optional `critical`
        _, ext_val = ext.read_tlv()
        _, general_names = ext_val.read_tlv(0x30)
        names = []
        while general_names.peek(1):
            tag, value = general_names.read_tlv()
            if tag == 0x82:  # dNSName [2] IA5String
                names.append(bytes(value.b).decode('ascii'))
        return names
    return []


def _check_basic_constraints(extensions: TlvReader) -> bool:
    for _, ext in extensions.iter_sequence_of_tlv(0x30):
        _, oid = ext.read_tlv()
        if oid.peek(100) != b'\x55\x1D\x13':  # 2.5.29.19, basic constraints
            continue
        if ext.peek(1) == b'\x01':
            ext.read_tlv()  # optional `critical`
        _, ext_val = ext.read_tlv()
        _, basic_constraints = ext_val.read_tlv()
        if basic_constraints.peek(1) == b'\x01':  # optonal boolean `cA`
            _, ca = basic_constraints.read_tlv()
            # 0xFF = TRUE, 0x00 = FALSE; leaf if cA=FALSE
            return ca.peek(1) == b'\x00'
    return True  # no info, it's leaf


@dataclass(frozen=True)
class CertInfo:
    is_leaf: bool
    not_before: datetime
    not_after: datetime
    domains: tuple[str, ...]


def parse_cert(pem: bytes) -> CertInfo:
    der = memoryview(_pem_to_der(pem))
    _, cert = TlvReader(der).read_tlv(0x30)
    _, tbs = cert.read_tlv(0x30)  # `tbsCertificate`, first field of cert
    if tbs.peek(1) == b'\xA0':  # optional `version`
        tbs.read_tlv()
    tbs.read_tlv()  # serialNumber
    tbs.read_tlv()  # signature
    tbs.read_tlv()  # issuer
    _, validity = tbs.read_tlv(0x30)  # validity
    _, subject = tbs.read_tlv()  # subject
    tbs.read_tlv()  # subjectPublicKeyInfo
    is_leaf = True
    san = []
    while tbs.peek(1):
        # optional `issuerUniqueID`, `subjectUniqueID`, `extensions`
        tag, extensions = tbs.read_tlv()
        if tag == 0xA3:
            _, exts = extensions.read_tlv(0x30)
            is_leaf = _check_basic_constraints(exts)
            exts.reset()
            san = _parse_san(exts)
            break
    not_before = _parse_time(*validity.read_tlv())
    not_after = _parse_time(*validity.read_tlv())
    if (
        (subject_cn := _parse_subject_cn(subject)) is not None
        and subject_cn not in san
    ):
        san.insert(0, subject_cn)
    return CertInfo(is_leaf, not_before, not_after, tuple(san))
