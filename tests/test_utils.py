import pytest

from acmeerkat.utils import is_valid_domain


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
])
def test_is_valid_domain(domain, valid):
    assert is_valid_domain(domain) == valid
