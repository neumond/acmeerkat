import subprocess
import tempfile
from dataclasses import dataclass

from acmeerkat import (
    BaseCrypto, Algorithm, KeyPairBytes, PublicKeyDict,
    b64_jose, JSONWebSignature, is_valid_curve_type)


__all__ = ('OpenSSLCrypto', )


@dataclass
class OpenSSLCrypto(BaseCrypto):
    # NOTE: requires tmpfs
    # NOTE: requires OpenSSL 1.1.1 or newer
    openssl_cmd: tuple[str] = ('openssl', )
    keep_stderr: bool = False  # debug openssl calls

    @property
    def _stderr(self):
        return None if self.keep_stderr else subprocess.DEVNULL

    def generate_key_pair(self, a: Algorithm) -> KeyPairBytes:
        if a is not Algorithm.ES256:
            raise ValueError(f'Unsupported algorithm {a}')
        # for longer keys try -name secp384r1 | secp521r1
        p = subprocess.run(
            [
                *self.openssl_cmd, 'ecparam', '-genkey',
                '-name', 'prime256v1',
                '-noout',  # TODO: really need this option?
                '-outform', 'DER',
            ],
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            check=True)
        return p.stdout

    def check_key_pair(self, key_pair: KeyPairBytes) -> bool:
        p = subprocess.run(
            [
                *self.openssl_cmd, 'ec', '-in', '/dev/stdin', '-check',
            ],
            input=key_pair,
            stdout=subprocess.DEVNULL,
            stderr=self._stderr,
            check=False)
        return p.returncode == 0

    @staticmethod
    def _parse_pubkey(t: str) -> PublicKeyDict:
        section = None
        is_private_key = False
        nist_curve = None
        pub_parts = []
        for line in t.splitlines():
            if not line:
                continue
            if not line[:1].isspace():
                section, line = line.split(':', 1)
                match section:
                    case 'Private-Key':
                        is_private_key = True
                    case 'NIST CURVE':
                        nist_curve = line.strip()
                continue
            match section:
                case 'pub':
                    pub_parts.append(
                        bytes.fromhex(line.strip().replace(':', '')))

        if not is_private_key:
            raise ValueError('Not a private key')
        if nist_curve is None:
            raise ValueError('No curve type detected')
        if not is_valid_curve_type(nist_curve):
            raise ValueError(f'Unsuppoted NIST curve: {nist_curve}')
        pub = b''.join(pub_parts)
        if not pub.startswith(b'\x04'):
            raise ValueError('Pubkey must start with 04 byte')
        pub = pub[1:]
        half = len(pub) // 2
        return {
            'crv': nist_curve,
            'kty': 'EC',
            'x': b64_jose(pub[:half]),
            'y': b64_jose(pub[half:])}

    def pubkey_params(self, key_pair: KeyPairBytes) -> PublicKeyDict:
        p = subprocess.run(
            [
                *self.openssl_cmd, 'ec', '-in', '/dev/stdin',
                '-noout', '-text',
            ],
            input=key_pair,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            check=True)
        return self._parse_pubkey(p.stdout.decode('ascii'))

    def sign(self, key_pair: KeyPairBytes, data: bytes) -> JSONWebSignature:
        with tempfile.NamedTemporaryFile(mode='wb') as tfile:
            tfile.write(data)
            tfile.flush()
            p = subprocess.run(
                [
                    # TODO: auto-pick hashing algo suitable for the key
                    *self.openssl_cmd, 'dgst', '-sha256',
                    # send sensitive data over anonymous pipe
                    '-sign', '/dev/stdin',
                    tfile.name,
                ],
                input=key_pair,
                stdout=subprocess.PIPE,
                stderr=self._stderr,
                check=True)
            signature_der = p.stdout
        p = subprocess.run(
            [
                *self.openssl_cmd, 'asn1parse',
                '-inform', 'DER',
            ],
            input=signature_der,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            check=True)
        p1, p2 = [
            bytes.fromhex(line.split(' :', 1)[1])
            for line in p.stdout.decode('ascii').splitlines()
            if ' :' in line]
        return b64_jose(p1 + p2)

    def generate_csr(
        self, key_pair: KeyPairBytes, domains: list[str],
    ) -> bytes:
        san = ', '.join(f'DNS:{d}' for d in domains)
        p = subprocess.run(
            [
                *self.openssl_cmd, 'req', '-new', '-sha256',
                # send sensitive data over anonymous pipe
                '-key', '/dev/stdin',
                '-subj', '/',
                '-addext', f'subjectAltName = {san}',
                '-outform', 'DER',
            ],
            input=key_pair,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            check=True)
        return p.stdout
