import base64
import urllib.parse
from pathlib import Path

from acmeerkat import (
    Algorithm,
    ProviderAccount,
    KVNamespace,
    CertUpdater,
    EcKeyParams,
    EcType,
    RsaKeyParams,
)
from acmeerkat.crypto.openssl import OpenSslCrypto
from acmeerkat.storage.file_pair import FilePairKVStorage
from acmeerkat.https.urllib import UrllibHttpsClient
from acmeerkat.challenge.http01 import ManualHttp01
from acmeerkat.challenge.dnspersist01 import DnsPersist01
from acmeerkat.pem import cert_chain_to_firefox_link


crypto = OpenSslCrypto(debug=True)
storage = FilePairKVStorage(Path('kv1.dat'), Path('kv2.dat'))
https_client = UrllibHttpsClient(debug=True)


def dump_storage(full=False):
    for k, v in storage._data.items():
        print(k, ':', v if full else v[:50])


def play_with_private_key_gen():
    alg = Algorithm.ES256
    kp = crypto.generate_key_pair(EcKeyParams(crv=EcType.P_256))
    print(kp)
    print()
    crypto.check_key_pair(kp)
    print(crypto.json_web_pub_key(kp))
    print()
    print(crypto.json_web_pub_key(kp).to_json())
    print()
    # print(kp)
    print('Repeated signatures:')
    for _ in range(3):
        print(crypto.sign(alg, kp, b'hello world'))


# play_with_private_key_gen()
# dump_storage(False)
# exit()

acc = ProviderAccount(
    directory_url='https://acme-staging-v02.api.letsencrypt.org/directory',
    storage_ns=KVNamespace(storage, b'staging_account/'),
    https_client=https_client,
    crypto=crypto,
    auto_create_account=False,
    alg=Algorithm.ES256,
    key_params=EcKeyParams(crv=EcType.P_256))

# replace existing key
# acc.storage_ns.update({
#     b'alg': acc.alg.to_bytes(),
#     b'keypair': crypto.generate_key_pair(acc.key_params)})
# acc._reload_alg_key()

dump_storage(False)
print('ACCOUNT', acc.account)
# print(acc.rollover_key())
dump_storage(False)
exit()
# print(acc.update_contacts())
# print(acc.update_tos_agreement(False))

# print('Put txt record `_validation-persist` on every domain:')
# print(acc.dns_persist_01_record(wildcard=True))

cu = CertUpdater(
    domains=['neumond.name', '*.neumond.name'],
    profile='tlsserver',
    account=acc,
    challenges=[DnsPersist01(debug=True)],
    storage_ns=KVNamespace(storage, b'certs/neumond.name/'))
cu.issue_new_certificate()
