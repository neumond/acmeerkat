# ACMEerkat: the ACMEv2 client library

## Another ACME client?

Many good clients already exist, yet they all strive to encapsulate the complexity of the ACME protocol within a single CLI utility so that users need think about as few aspects as possible. While this is a meritorious goal in its own right, it makes such tools notoriously difficult to adapt to more convoluted scenarios.

Consider, for example, a Kubernetes environment: you probably want to install a certificate as a Secret object (since it contains the certificate's private key), yet you will have to store ACME account data and certificate history (a few hundred kilobytes) in an entire volume, which introduces operational complexity. All of that could instead be stored in just another Secret object, directly on the Kubernetes control plane.

What if you want to replace not only the storage but also the HTTP client or the crypto engine? Most tools offer no tangible means of doing so. What if you want to control ACME accounts themselves — rolling over account keys, changing their crypto algorithms, or issuing specific certificates with specific accounts? Most likely, there is no easy way to do any of this.

## Auditability

Most of the _tiny_ clients try to pack all their code into a single file of roughly 1000 lines so that you can read it yourself. ACMEerkat does not do this. Instead, it adopts a meaningful package structure, attempting to isolate trivial boilerplate — such as lists of errors — into a separate module. As a result, you need only read the core thoughtfully; it is even less than 1000 lines and contains no heavy cryptography, since that is decoupled into BaseCrypto subclasses with a clean API.

All ABC implementations in the subpackages are completely replaceable. In fact, you may even delete the modules you will not use and bring your own. They will never be implicitly imported.

## Easy to install

Simply zip the acmeerkat directory and put that single file on your server (see what `cmd__zip` in [make.fish](make.fish) does). It's as simple as downloading that other single-file client. Only python3 is required to run it; it doesn't even need pip.

If you do want to use pip, it's trivial: `pip install acmeerkat`.

While some people prefer bash for its ubiquity, I see no real benefit in using it for ACME. The task requires some parsing and encoding (especially json), and bash without a host of supplementary utilities is quite alien to this. It would be difficult to use as a library, bash is a bad programming language. Moreover, most server operating systems have Python pre-installed anyway.

## Dependency injection instead hooks and plugins

The project strives to make everything as clear as possible. A first glance at the types must be enough to know how to use anything. Even more, looking at the ACMEerkat API is the easiest way to learn the general structure and capabilities of the ACME protocol.

## How to use

You'll need `openssl` cmdline utility and acmeerkat downloaded as zip archive.

```py
import os
import signal
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, 'acmeerkat.0.2.0.zip')

from acmeerkat import Account, KVNamespace, CertUpdater, DirectoryUrl
from acmeerkat.challenge.dnspersist01 import DnsPersist01
from acmeerkat.crypto.openssl import OpenSslCrypto
from acmeerkat.https.urllib import UrllibHttpsClient
from acmeerkat.storage.file_pair import FilePairKVStorage

crypto = OpenSslCrypto()
storage = FilePairKVStorage(Path('kv1.dat'), Path('kv2.dat'))
https_client = UrllibHttpsClient()
reload_nginx = False

account1 = Account(
    id='account1',
    storage=storage,
    https_client=https_client,
    crypto=crypto,
    next_alg_params=Ec384())
account1.refresh()

if not account1.is_valid():
    account1.register(
        directory_url=DirectoryUrl.letsencrypt_staging,
        contacts=('mailto:hello@example.org', ))

if (
    account1.will_change_any(alg_params=True)
    or account1.get_key_age() >= timedelta(days=90)
):
    account1.rollover_key()

cu = CertUpdater(
    id='example.org',
    account=account1,
    next_domains=('example.org', '*.example.org'),
    next_alg_params=Ec384(),
    next_profile='tlsserver')

if (
    cu.will_change_any(domains=True, alg_params=True)
    or cu.get_remaining_validity() <= timedelta(days=3)
):
    if cu.issue_new_certificate(challenges=(DnsPersist01(), )):
        print('✅ Issued new certificate')
        cu.get_bundle().write_nginx_files(
            cert_chain='/etc/nginx/certs/example.org.crt',
            private_key='/etc/nginx/certs/example.org.key')
        reload_nginx = True
    else:
        print('❌ Failed to issue a certificate')
else:
    print('Not yet to be updated')

if reload_nginx:
    pid = int(Path('/run/nginx.pid').read_text())
    os.kill(pid, signal.SIGHUP)
    print('✅ Reloaded nginx')
```
