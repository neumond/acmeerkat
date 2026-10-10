# ACMEerkat: the ACME client

## Why another ACME client?

I want to build a fully customizable and programmable client with a clean API, rather than yet another ordinary CLI utility that optimizes a single happy path for delivering a certificate. Everything must be replaceable, including even the HTTP client. The core must be easy to audit and must consist only of simple, readable, structured code, rather than a thousand lines of compressed cryptographic magic.

It would not be written in Bash. Bash is hard to read and hard to write. The task is complex enough that using Python yields substantial benefits, yet it is not demanding enough to require compiled languages. While Bash is ubiquitous and installing a single-file script is a no-brainer, making it work correctly is hard. You always have to experiment to figure out things like the resulting file layout, and you cannot simply import the script and use its API to do the precise thing you need; it is always a complex command-line utility.

Storing all the data as regular files does not fit every setup. On Kubernetes, it could be better to avoid using volumes and instead store certificates and related data in native objects such as ConfigMaps and Secrets. Wildcard certificates could be shared with several remote machines. You may want to use different Let's Encrypt accounts for different certificates. The ways to install and apply a new certificate vary greatly depending on the environment (e.g., containers) and the HTTP server used, especially if you want to increase safety by dropping as many privileges as possible.

No hooks, no plugins — just plain old OOP and DI. Automate precisely what you want, and even if you don't know the details of the ACME protocol, the API will give you an intuitive feel for it.

## How to use

You'll need `openssl` cmdline utility and installed python package:

```sh
pip install acmeerkat
```

Alternatively, you may simply copy `acmeerkat/` dir from this repository or create importable zip file (`./make.fish zip`). It's pure python. You may even delete unused modules in subpackages.

```py
import os
import signal
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, 'acmeerkat.0.1.0.zip')

from acmeerkat import ProviderAccount, KVNamespace, CertUpdater
from acmeerkat.challenge.dnspersist01 import DnsPersist01
from acmeerkat.crypto.openssl import OpenSslCrypto
from acmeerkat.https.urllib import UrllibHttpsClient
from acmeerkat.storage.file_pair import FilePairKVStorage

crypto = OpenSslCrypto()
storage = FilePairKVStorage(Path('kv1.dat'), Path('kv2.dat'))
https_client = UrllibHttpsClient()
reload_nginx = False

account1 = ProviderAccount(
    directory_url='https://acme-staging-v02.api.letsencrypt.org/directory',
    storage_ns=KVNamespace(storage, b'account1/'),
    https_client=https_client,
    crypto=crypto)

cu = CertUpdater(
    domains=['example.org', '*.example.org'],
    profile='tlsserver',
    account=account1,
    challenges=[DnsPersist01()],
    storage_ns=KVNamespace(storage, b'certs/example.org/'))

if cu.get_remaining_validity() <= timedelta(days=3):
    cu.issue_new_certificate()
    print('✅ Issued new certificate')
    cu.write_nginx_files(
        cert_chain='/etc/nginx/certs/example.org.crt',
        private_key='/etc/nginx/certs/example.org.key')
    reload_nginx = True
else:
    print('Not yet to be updated')

if reload_nginx:
    pid = int(Path('/run/nginx.pid').read_text())
    os.kill(pid, signal.SIGHUP)
    print('✅ Restarted nginx')
```
