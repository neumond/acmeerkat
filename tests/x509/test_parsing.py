"""
Downloading a certchain:

openssl s_client -connect example.org:443
-showcerts < /dev/null > example.org.chain.pem
"""

import re
import subprocess
from collections import abc
from datetime import datetime, timezone
from pathlib import Path

import pytest

from acmeerkat.x509 import parse_cert


def _load_chains(d: Path) -> abc.Iterator[Path]:
    for f in d.glob('*.chain.pem'):
        yield pytest.param(f, id=f.name)


# avoiding strptime to be locale-independent
# "Jul 16 03:06:35 2025 GMT"
_DATE_RE = re.compile(
    r'(?P<mo>[A-Z][a-z]{2})'
    r'\s+(?P<d>[0-9]{1,2})\s+'
    r'(?P<h>[0-9]{2}):(?P<m>[0-9]{2}):(?P<s>[0-9]{2})'
    r'\s+(?P<y>[0-9]{4})\s+GMT')
_MONTHS = 'Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec'.split('|')


def _parse_openssl_date(d: str) -> datetime:
    if (m := _DATE_RE.match(d.strip())) is None:
        raise ValueError
    return datetime(
        int(m['y']), _MONTHS.index(m['mo']) + 1, int(m['d']),
        int(m['h']), int(m['m']), int(m['s']),
        tzinfo=timezone.utc)


def _iter_certs(f: Path) -> abc.Iterator[
    tuple[bytes, bool, datetime, datetime],
]:
    line_it = f.open('r')
    while (line := next(line_it)) != 'Certificate chain\n':
        pass
    first = True
    while True:
        try:
            while 'v:NotBefore:' not in (line := next(line_it)):
                assert '-----BEGIN CERTIFICATE-----' not in line
        except StopIteration:
            break
        not_before, not_after = (
            line.split('v:NotBefore:', 1)[1].split('; NotAfter:', 1))

        pem = []
        while '-----BEGIN CERTIFICATE-----\n' != (line := next(line_it)):
            pass
        pem.append(line)
        while '-----END CERTIFICATE-----\n' != (line := next(line_it)):
            pem.append(line)
        pem.append(line)

        yield (
            ''.join(pem).encode('ascii'),
            first,  # first cert is always a leaf
            _parse_openssl_date(not_before),
            _parse_openssl_date(not_after))
        first = False


def get_cert_domains(pem):
    p = subprocess.run(
        [
            'openssl', 'x509', '-in', '/dev/stdin',
            '-noout', '-text',
        ],
        input=pem,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True)

    r = set()
    pos = p.stdout.index(b'Subject: ')
    epos = p.stdout.index(b'\n', pos)
    for i in (
        p.stdout[pos:epos].decode('utf-8')
        .removeprefix('Subject: ').strip().split(',')
    ):
        i = i.strip()
        if i.startswith('CN='):
            r.add(i.removeprefix('CN='))

    pos = p.stdout.find(b'X509v3 Subject Alternative Name:')
    if pos >= 0:
        pos = p.stdout.index(b'\n', pos) + 1
        epos = p.stdout.index(b'\n', pos)
        for i in p.stdout[pos:epos].decode('utf-8').strip().split(','):
            i = i.strip()
            assert i.startswith('DNS:')
            r.add(i.removeprefix('DNS:'))

    return frozenset(r)


@pytest.mark.parametrize('chainfile', _load_chains(Path(__file__).parent))
def test_chain(chainfile: Path) -> None:
    for pem, leaf, nb, na in _iter_certs(chainfile):
        cinfo = parse_cert(pem)
        assert cinfo.is_leaf == leaf
        assert cinfo.not_before == nb
        assert cinfo.not_after == na
        assert frozenset(cinfo.domains) == get_cert_domains(pem)
