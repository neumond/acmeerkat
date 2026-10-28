from datetime import datetime, timedelta, timezone

import pytest

from acmeerkat.utils import is_valid_domain, bin_isoformat, bin_fromisoformat


@pytest.mark.parametrize('domain,valid', [
    ('example.org', True),
    ('com', False),
    ('sub.example.co.uk', True),
    ('xn--bcher-kva.de', True),
    ('xn--bcher-kva.example.com', True),
    ('my-site.example.com', True),
    ('-example.com', False),
    ('example-.com', False),
    ('--example.com', False),
    ('example--.com', False),
    ('test.xn--p1ai', True),
    ('----.com', False),
    ('----', False),
    ('', False),
    ('-', False),
    ('.', False),
    ('.com', False),
    ('..com', False),
    ('domain..com', False),
    ('.domain.com', False),
    ('..domain.com', False),
    ('domain.abc.com', True),
    ('000.com', True),
    ('0.1.2.3.4.5.6.7.com', True),
    pytest.param(('sub.' * 10) + 'domain.com', True, id='longer'),
    pytest.param(('sub.' * 100) + 'domain.com', False, id='too_long'),
    ('*.example.org', True),  # allow wildcards
    ('*.sub.example.org', True),
    ('*.*.example.org', False),
    ('**.example.org', False),
    ('*', False),
    ('*.*', False),
    ('**.example.org', False),
    ('sub.*.example.org', False),
    ('münchen.de', False),  # require punycode
    ('бүргэд.мон', False),
    (' example.org', False),
    ('example.org ', False),
])
def test_is_valid_domain(domain, valid):
    assert is_valid_domain(domain) == valid


@pytest.mark.parametrize('d', [
    datetime.now(tz=timezone.utc),
    datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
])
def test_isoformat_roundtrip(d):
    bs = bin_isoformat(d)
    assert bin_fromisoformat(bs) == d
    assert bs.endswith(b'Z')


@pytest.mark.parametrize('d', [
    datetime.now(),
    datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=5))),
])
def test_isoformat_requires_utc(d):
    with pytest.raises(ValueError):
        bin_isoformat(datetime.now())
