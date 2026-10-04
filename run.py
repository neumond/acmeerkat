from pathlib import Path

from acmeerkat import ProviderAccount, KVNamespace, CertUpdater
from acmeerkat.crypto.openssl import OpenSSLCrypto
from acmeerkat.storage.file_pair import FilePairKVStorage
from acmeerkat.https.urllib import UrllibHTTPSClient
from acmeerkat.challenge.http01 import ManualHTTP01


crypto = OpenSSLCrypto()
# kp = crypto.generate_key_pair(Algorithm.ES256)
# crypto.check_key_pair(kp)
# print(crypto.pubkey_params(kp))
# print(kp)
# print(crypto.sign(kp, b'hello world'))

storage = FilePairKVStorage(Path('kv1.dat'), Path('kv2.dat'))
https_client = UrllibHTTPSClient(
    directory_url='https://acme-staging-v02.api.letsencrypt.org/directory')
acc = ProviderAccount(
    contacts=[],
    storage_ns=KVNamespace(storage, b'staging_account/'),
    https_client=https_client,
    crypto=crypto)

cu = CertUpdater(
    domains=['test.neumond.name'],
    profile='tlsserver',
    account=acc,
    challenges=[ManualHTTP01()],
    storage_ns=KVNamespace(storage, b'certs/test.neumond.name/'))
cu._issue_new_certificate()
