from pathlib import Path

from acmeerkat import Algorithm, ProviderAccount, KVNamespace, CertUpdater
from acmeerkat.crypto.openssl import OpenSslCrypto
from acmeerkat.storage.file_pair import FilePairKVStorage
from acmeerkat.https.urllib import UrllibHttpsClient
from acmeerkat.challenge.http01 import ManualHTTP01
from acmeerkat import jwk


crypto = OpenSslCrypto(debug=True)
storage = FilePairKVStorage(Path('kv1.dat'), Path('kv2.dat'))


def patch_storage():
    KVNamespace(storage, b'staging_account/').update({
        b'alg': b'ES256',
    })


def dump_storage():
    for k, v in storage._data.items():
        print(k, v[:50])


kp = crypto.generate_key_pair(jwk.EcKeyParams(crv=jwk.EcType.P_256))
print(kp)
print()
crypto.check_key_pair(kp)
print(crypto.json_web_pub_key(kp))
print()
print(crypto.json_web_pub_key(kp).to_json())
# print(kp)
# print(crypto.sign(kp, b'hello world'))

exit()

storage = FilePairKVStorage(Path('kv1.dat'), Path('kv2.dat'))
https_client = UrllibHttpsClient(debug=True)
acc = ProviderAccount(
    directory_url='https://acme-staging-v02.api.letsencrypt.org/directory',
    contacts=[],
    storage_ns=KVNamespace(storage, b'staging_account/'),
    https_client=https_client,
    crypto=crypto)
print('ACCOUNT', acc.account)


acc_json = acc._do_signed_request(acc.account['__Location'], '')
print(acc_json)


# cu = CertUpdater(
#     domains=['test.neumond.name'],
#     profile='tlsserver',
#     account=acc,
#     challenges=[ManualHTTP01()],
#     storage_ns=KVNamespace(storage, b'certs/test.neumond.name/'))
# cu._issue_new_certificate()
