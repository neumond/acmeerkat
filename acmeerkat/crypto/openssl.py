import subprocess
import tempfile
from dataclasses import dataclass

from acmeerkat import (
    BaseCrypto, Algorithm, KeyPairBytes,
    b64_jose, JSONWebSignature)
from acmeerkat import jwk


__all__ = ('OpenSslCrypto', )


ALG_HASH = {
    Algorithm.ES256: '-sha256',
    Algorithm.ES384: '-sha384',
    Algorithm.ES512: '-sha512',

    Algorithm.RS256: '-sha256',
    Algorithm.RS384: '-sha384',
    Algorithm.RS512: '-sha512',

    Algorithm.PS256: '-sha256',
    Algorithm.PS384: '-sha384',
    Algorithm.PS512: '-sha512',

    # TODO: EdDSA
}


@dataclass
class OpenSslCrypto(BaseCrypto):
    # NOTE: requires tmpfs
    # NOTE: requires OpenSSL 1.1.1 or newer
    openssl_cmd: tuple[str] = ('openssl', )
    debug: bool = False  # debug openssl calls

    @property
    def _stderr(self):
        return None if self.debug else subprocess.DEVNULL

    def generate_key_pair(self, params: jwk.BaseKeyParams) -> KeyPairBytes:
        gpk = []
        match params:
            case jwk.EcKeyParams():
                gpk.extend([
                    '-algorithm', 'EC',
                    '-pkeyopt', f'ec_paramgen_curve:{params.crv.value}',
                    '-pkeyopt', 'ec_param_enc:named_curve'])
            case jwk.RsaKeyParams():
                gpk.extend([
                    '-algorithm', 'RSA',
                    '-pkeyopt', f'rsa_keygen_bits:{params.bits}',
                    '-pkeyopt', f'rsa_keygen_primes:{params.primes}',
                    '-pkeyopt', f'rsa_keygen_pubexp:{params.pubexp}'])
            case jwk.RsaPssKeyParams():
                gpk.extend([
                    '-algorithm', 'RSA-PSS',
                    '-pkeyopt', f'rsa_keygen_bits:{params.bits}',
                    '-pkeyopt', f'rsa_keygen_primes:{params.primes}',
                    '-pkeyopt', f'rsa_keygen_pubexp:{params.pubexp}'])
                if params.md is not None:
                    gpk.extend([
                        '-pkeyopt',
                        f'rsa_pss_keygen_md:{params.md}'])
                if params.mgf1 is not None:
                    gpk.extend([
                        '-pkeyopt',
                        f'rsa_pss_keygen_mgf1_md:{params.mgf1}'])
                if params.saltlen is not None:
                    gpk.extend([
                        '-pkeyopt',
                        f'rsa_pss_keygen_saltlen:{params.saltlen}'])
            case jwk.EdKeyParams():
                gpk.extend([
                    '-algorithm', params.crv.value.upper()])
        p = subprocess.run(
            [
                *self.openssl_cmd, 'genpkey', *gpk,
                '-outform', 'DER',
            ],
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            check=True)
        return p.stdout

    def check_key_pair(self, key_pair: KeyPairBytes) -> bool:
        p = subprocess.run(
            [
                *self.openssl_cmd, 'pkey',
                # send sensitive data over anonymous pipe
                '-in', '/dev/stdin',
                '-check',
            ],
            input=key_pair,
            stdout=subprocess.DEVNULL,
            stderr=self._stderr,
            check=False)
        return p.returncode == 0

    @staticmethod
    def _parse_pubkey(t: str) -> jwk.BaseJsonWebPubKey:
        # print(t)
        section: str = ''
        hex_section_parts: dict[str, list[bytes]] = {}
        single_line_sections = {}
        for line in t.splitlines():
            if not line:
                continue
            if not line[:1].isspace():
                section, line = line.split(':', 1)
                line = line.strip()
                if line:
                    single_line_sections[section] = line
                continue
            if section not in hex_section_parts:
                hex_section_parts[section] = []
            hex_section_parts[section].append(
                bytes.fromhex(line.strip().replace(':', '')))

        if single_line_sections.get('Private-Key') is None:
            raise ValueError('Not a private key')

        if (
            'pub' in hex_section_parts
            and 'NIST CURVE' in single_line_sections
        ):
            pub = b''.join(hex_section_parts['pub'])
            if not pub.startswith(b'\x04'):
                raise ValueError('EC pubkey must start with 04 byte')
            pub = pub[1:]
            half = len(pub) // 2
            return jwk.EcJsonWebPubKey(
                crv=jwk.CurveType(single_line_sections['NIST CURVE']),
                x=pub[:half],
                y=pub[half:])

        if (
            'modulus' in hex_section_parts
            and 'publicExponent' in single_line_sections
        ):
            return jwk.RsaJsonWebPubKey(
                n=b''.join(hex_section_parts['modulus']),
                e=int(single_line_sections['publicExponent'].split(' ', 1)[0]))

        raise ValueError('Unknown key type')

    def json_web_pub_key(
        self, key_pair: KeyPairBytes,
    ) -> jwk.BaseJsonWebPubKey:
        p = subprocess.run(
            [
                *self.openssl_cmd, 'pkey',
                # send sensitive data over anonymous pipe
                '-in', '/dev/stdin',
                '-noout', '-text',
            ],
            input=key_pair,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            check=True)
        return self._parse_pubkey(p.stdout.decode('ascii'))

    def sign(
        self,
        alg: Algorithm,
        key_pair: KeyPairBytes,
        data: bytes,
    ) -> JSONWebSignature:
        with tempfile.NamedTemporaryFile(mode='wb') as tfile:
            tfile.write(data)
            tfile.flush()
            p = subprocess.run(
                [
                    *self.openssl_cmd, 'dgst', ALG_HASH[alg],
                    # send sensitive data over anonymous pipe
                    '-sign', '/dev/stdin',
                    tfile.name,
                ],
                input=key_pair,
                stdout=subprocess.PIPE,
                stderr=self._stderr,
                check=True)
            signature = p.stdout
        match self.json_web_pub_key(key_pair):
            case jwk.EcJsonWebPubKey(crv):
                p = subprocess.run(
                    [
                        *self.openssl_cmd, 'asn1parse',
                        '-inform', 'DER',
                    ],
                    input=signature,
                    stdout=subprocess.PIPE,
                    stderr=self._stderr,
                    check=True)
                p1, p2 = [
                    bytes.fromhex(line.split(' :', 1)[1])
                    for line in p.stdout.decode('ascii').splitlines()
                    if ' :' in line]
                # apply padding
                # asn1 keeps signature as 2 integers
                # with variable size binary representation
                match crv:
                    case jwk.CurveType.P_256:
                        s = 32
                    case jwk.CurveType.P_384:
                        s = 48
                    case jwk.CurveType.P_521:
                        s = 66
                p1 = p1.rjust(s, b'\0')
                p2 = p2.rjust(s, b'\0')
                return b64_jose(p1 + p2)
            case jwk.RsaJsonWebPubKey():
                return b64_jose(signature)
        raise ValueError

    def generate_csr(
        self,
        alg: Algorithm,
        key_pair: KeyPairBytes,
        domains: list[str],
    ) -> bytes:
        san = ', '.join(f'DNS:{d}' for d in domains)
        p = subprocess.run(
            [
                *self.openssl_cmd, 'req', '-new', ALG_HASH[alg],
                # send sensitive data over anonymous pipe
                '-key', '/dev/stdin',
                # recommended in LE docs
                # to drop canonical name
                # and use SAN instead
                '-subj', '/',
                '-addext', f'subjectAltName = {san}',
                '-outform', 'DER',
            ],
            input=key_pair,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            check=True)
        return p.stdout
