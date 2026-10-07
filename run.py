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
from acmeerkat.challenge.http01 import ManualHTTP01


crypto = OpenSslCrypto(debug=True)
storage = FilePairKVStorage(Path('kv1.dat'), Path('kv2.dat'))
https_client = UrllibHttpsClient(debug=True)


def dump_storage(full=False):
    for k, v in storage._data.items():
        print(k, v if full else v[:50])


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


# dump_storage(False)
# play_with_private_key_gen()
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

print('ACCOUNT', acc.account)
# print(acc.update_contacts())
# print(acc.rollover_key())
print(acc.update_tos_agreement(False))
exit()

# acc_json = acc._do_signed_request(acc.account['__Location'], '')
# print(acc_json)


# cu = CertUpdater(
#     domains=['test.neumond.name'],
#     profile='tlsserver',
#     account=acc,
#     challenges=[ManualHTTP01()],
#     storage_ns=KVNamespace(storage, b'certs/test.neumond.name/'))
# cu._issue_new_certificate()
