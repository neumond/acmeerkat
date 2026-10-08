import subprocess
import tempfile
from dataclasses import dataclass

from acmeerkat import (
    Algorithm,
    BaseCrypto,
    BaseJsonWebPubKey,
    BaseKeyParams,
    EcJsonWebPubKey,
    EcKeyParams,
    EcType,
    EdJsonWebPubKey,
    EdKeyParams,
    EdVariant,
    PrivateKey,
    RsaJsonWebPubKey,
    RsaKeyParams,
    RsaPssKeyParams,
)


__all__ = ('OpenSslCrypto', )


ALG_EXPLICIT_HASH = {
    Algorithm.RS256: '-sha256',
    Algorithm.RS384: '-sha384',
    Algorithm.RS512: '-sha512',

    Algorithm.PS256: '-sha256',
    Algorithm.PS384: '-sha384',
    Algorithm.PS512: '-sha512',
}
RSA_PSS_PARAMS = {
    Algorithm.PS256: ('sha256', '32'),
    Algorithm.PS384: ('sha384', '48'),
    Algorithm.PS512: ('sha512', '64'),
}
RSA_PSS_HASHALG = {
    'SHA2-256': Algorithm.PS256,
    'SHA2-384': Algorithm.PS384,
    'SHA2-512': Algorithm.PS512,
}


@dataclass
class OpenSslCrypto(BaseCrypto):
    # NOTE: requires tmpfs
    # NOTE: requires OpenSSL 1.1.1 or newer
    openssl_cmd: tuple[str] = ('openssl', )
    debug: bool = False  # debug openssl calls

    @property
    def _stderr(self) -> int | None:
        return None if self.debug else subprocess.DEVNULL

    def generate_key_pair(self, params: BaseKeyParams) -> PrivateKey:
        gpk = []
        match params:
            case EcKeyParams():
                gpk.extend([
                    '-algorithm', 'EC',
                    '-pkeyopt', f'ec_paramgen_curve:{params.crv.value}',
                    '-pkeyopt', 'ec_param_enc:named_curve'])
            case RsaKeyParams():
                gpk.extend([
                    '-algorithm', (
                        'RSA-PSS'
                        if isinstance(params, RsaPssKeyParams) else
                        'RSA'),
                    '-pkeyopt', f'rsa_keygen_bits:{params.bits}',
                    '-pkeyopt', f'rsa_keygen_primes:{params.primes}',
                    '-pkeyopt', f'rsa_keygen_pubexp:{params.pubexp}'])
                if isinstance(params, RsaPssKeyParams):
                    h, salt = RSA_PSS_PARAMS[params.alg]
                    gpk.extend([
                        '-pkeyopt', f'rsa_pss_keygen_md:{h}',
                        '-pkeyopt', f'rsa_pss_keygen_mgf1_md:{h}',
                        '-pkeyopt', f'rsa_pss_keygen_saltlen:{salt}'])
            case EdKeyParams():
                gpk.extend([
                    '-algorithm', params.crv.value.upper()])
        p = subprocess.run(
            [
                *self.openssl_cmd, 'genpkey', *gpk,
                '-outform', 'PEM',
            ],
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            check=True)
        return p.stdout

    def check_key_pair(self, key_pair: PrivateKey) -> bool:
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
    def _parse_pubkey(t: str) -> BaseJsonWebPubKey:
        print(t)
        section: str = ''
        hex_section_parts: dict[str, list[bytes]] = {}
        single_line_sections = {}
        for line in t.splitlines():
            if not line:
                continue
            if not line[:1].isspace():
                section, line = line.split(':', 1)
                single_line_sections[section] = line.strip()
                continue
            if section == 'PSS parameter restrictions':
                k, v = line.strip().split(':', 1)
                single_line_sections[f'PSS {k}'] = v.strip()
                continue
            if section not in hex_section_parts:
                hex_section_parts[section] = []
            hex_section_parts[section].append(
                bytes.fromhex(line.strip().replace(':', '')))

        if (
            'Private-Key' in single_line_sections
            and 'pub' in hex_section_parts
            and 'NIST CURVE' in single_line_sections
        ):
            pub = b''.join(hex_section_parts['pub'])
            if not pub.startswith(b'\x04'):
                raise ValueError('EC pubkey must start with 04 byte')
            pub = pub[1:]
            half = len(pub) // 2
            return EcJsonWebPubKey(
                crv=EcType(single_line_sections['NIST CURVE']),
                x=pub[:half],
                y=pub[half:])

        if (
            'Private-Key' in single_line_sections
            and 'modulus' in hex_section_parts
            and 'publicExponent' in single_line_sections
        ):
            alg = None
            if 'PSS Hash Algorithm' in single_line_sections:
                alg = RSA_PSS_HASHALG[single_line_sections[
                    'PSS Hash Algorithm']]
            return RsaJsonWebPubKey(
                n=b''.join(hex_section_parts['modulus']),
                e=int(single_line_sections['publicExponent'].split(' ', 1)[0]),
                alg=alg)

        if (
            'ED25519 Private-Key' in single_line_sections
            and 'priv' in hex_section_parts
        ):
            return EdJsonWebPubKey(
                crv=EdVariant.Ed25519,
                x=b''.join(hex_section_parts['priv']))

        if (
            'ED448 Private-Key' in single_line_sections
            and 'priv' in hex_section_parts
        ):
            return EdJsonWebPubKey(
                crv=EdVariant.Ed448,
                x=b''.join(hex_section_parts['priv']))

        raise ValueError('Unknown key type')

    def json_web_pub_key(
        self, key_pair: PrivateKey,
    ) -> BaseJsonWebPubKey:
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
        key_pair: PrivateKey,
        data: bytes,
    ) -> bytes:
        cmd = []
        if (h := ALG_EXPLICIT_HASH.get(alg, None)):
            cmd.append(h)
        if alg in (
            Algorithm.PS256,
            Algorithm.PS384,
            Algorithm.PS512,
        ):
            cmd.extend(['-sigopt', 'rsa_padding_mode:pss'])

        with tempfile.NamedTemporaryFile(mode='wb') as tfile:
            tfile.write(data)
            tfile.flush()
            p = subprocess.run(
                [
                    *self.openssl_cmd, 'dgst', *cmd,
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
            case EcJsonWebPubKey(crv):
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
                    case EcType.P_256:
                        s = 32
                    case EcType.P_384:
                        s = 48
                    case EcType.P_521:
                        s = 66
                p1 = p1.rjust(s, b'\0')
                p2 = p2.rjust(s, b'\0')
                return p1 + p2
            case RsaJsonWebPubKey() | EdJsonWebPubKey():
                return signature
        raise ValueError

    def generate_csr(
        self,
        alg: Algorithm,
        key_pair: PrivateKey,
        domains: list[str],
    ) -> bytes:
        cmd = []
        if (h := ALG_EXPLICIT_HASH.get(alg, None)):
            cmd.append(h)
        san = ', '.join(f'DNS:{d}' for d in domains)
        p = subprocess.run(
            [
                *self.openssl_cmd, 'req', '-new', *cmd,
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
