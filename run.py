import os
import signal
import traceback
from datetime import timedelta
from pathlib import Path

from acmeerkat import ProviderAccount, KVNamespace, CertUpdater, periodic
from acmeerkat.challenge.dnspersist01 import DnsPersist01
from acmeerkat.crypto.openssl import OpenSslCrypto
from acmeerkat.https.urllib import UrllibHttpsClient
from acmeerkat.storage.file_pair import FilePairKVStorage


def update_all_certs():
    output = []
    crypto = OpenSslCrypto(debug=True)
    storage = FilePairKVStorage(Path('kv1.dat'), Path('kv2.dat'))
    https_client = UrllibHttpsClient(debug=True)
    reload_nginx = False

    acc = ProviderAccount(
        directory_url='https://acme-staging-v02.api.letsencrypt.org/directory',
        storage_ns=KVNamespace(storage, b'staging_account/'),
        https_client=https_client,
        crypto=crypto)

    cu = CertUpdater(
        domains=['example.org', '*.example.org'],
        profile='tlsserver',
        account=acc,
        challenges=[DnsPersist01(debug=True)],
        storage_ns=KVNamespace(storage, b'certs/example.org/'))

    if cu.get_remaining_validity() <= timedelta(days=3):
        cu.issue_new_certificate()
        output.append('✅ Issued new certificate')
        cu.write_nginx_files(
            cert_chain='/etc/nginx/certs/example.org.crt',
            private_key='/etc/nginx/certs/example.org.key')
        reload_nginx = True
    else:
        output.append('Not yet to be updated')

    if reload_nginx:
        pid = int(Path('/run/nginx.pid').read_text())
        os.kill(pid, signal.SIGHUP)
        output.append('✅ Restarted nginx')

    return '\n'.join(output)


def dump_storage(full=False):
    storage = FilePairKVStorage(Path('kv1.dat'), Path('kv2.dat'))
    for k, v in storage._data.items():
        print(k, ':', v if full else v[:50])


dump_storage(False)
exit()


def report(message):
    print(message)


for _ in periodic(86400., 7200.):
    try:
        report(update_all_certs())
    except Exception as e:
        report('‼️' + ''.join(traceback.extract_tb(e.__traceback__)))
