from typing import Any, Protocol

from .core import Account, CertUpdater


__all__ = (
    'dump_account',
    'dump_cert_updater',
)


class TablePrintFn(Protocol):
    def __call__(self, key: str, value: Any, raw: bool = False) -> None:
        ...


def make_table_print(ksize: int) -> TablePrintFn:
    fmt = f'{{key:>{ksize}}}: {{value}}'

    def tprint(key: str, value: Any, raw: bool = False) -> None:
        print(fmt.format(key=key, value=value if raw else repr(value)))
    return tprint


def dump_account(acc: Account) -> None:
    tprint = make_table_print(25)
    print('ACCOUNT ------------------')
    tprint('id', acc.id)
    tprint('exists()', (ex := acc.exists()))
    if not ex:
        return
    tprint('is_valid()', (val := acc.is_valid()))
    tprint('directory_url', acc.directory_url)
    tprint('directory', acc.directory)
    tprint('alg_params', acc.alg_params)
    tprint('private_key size', len(acc.private_key))
    tprint('key_generated_at', acc.key_generated_at)
    tprint('contacts', acc.contacts)
    tprint('agreed_to_tos', acc.agreed_to_tos)
    tprint('account_url', acc.account_url)
    tprint('account', acc.account)
    dr = acc.get_dns_persist_01_record()
    dw = acc.get_dns_persist_01_record(wildcard=True)
    tprint(
        'dns-persist-01', f'_validation-persist.<domain> TXT {dr!r}', raw=True)
    tprint(
        '... wildcard', f'_validation-persist.<domain> TXT {dw!r}', raw=True)
    if not val:
        tprint('not valid', 'You\'ll have to register a new account', raw=True)
    print()


def dump_cert_updater(cu: CertUpdater) -> None:
    tprint = make_table_print(25)
    print('CERT UPDATER ----------------')
    tprint('id', cu.id)
    tprint('account.id', cu.account.id)
    tprint('will_change domains', cu.will_change_any(domains=True))
    tprint('... alg_params', cu.will_change_any(alg_params=True))
    tprint('... profile', cu.will_change_any(profile=True))
    tprint('get_remaining_validity()', cu.get_remaining_validity())
    tprint('has_unfinished_order()', cu.has_unfinished_order())
    tprint('next_domains', cu.next_domains)
    tprint('next_alg_params', cu.next_alg_params)
    tprint('next_profile', cu.next_profile)
    tprint('bundles', '', raw=True)
    i = 0
    for i, b in enumerate(cu.iter_bundles(), start=1):
        print()
        tprint('#', i)
        tprint('alg_params', b.alg_params)
        tprint('profile', b.profile)
        cinfo = b.get_leaf_cert_info()
        tprint('cert_info not_before', cinfo.not_before)
        tprint('... not_after', cinfo.not_after)
        tprint('... domains', cinfo.domains)
        tprint('private key size', len(b.private_key))
        tprint('cert chain sizes', [len(cx) for cx in b.cert_chain])
    if i == 0:
        tprint('', 'no bundles')
    print()
