import subprocess
import tempfile
from dataclasses import dataclass
from typing import cast, Literal

from acmeerkat import (
    BaseCrypto,
    BaseJsonWebPubKey,
    EcJsonWebPubKey,
    EdJsonWebPubKey,
    PrivateKey,
    RsaJsonWebPubKey,
)
from acmeerkat import alg_params as ap


__all__ = ('OpenSslCrypto', )


HASH_BY_ALG = {
    'RS256': '-sha256',
    'RS384': '-sha384',
    'RS512': '-sha512',

    'PS256': '-sha256',
    'PS384': '-sha384',
    'PS512': '-sha512',
}
EC_CURVE = {
    ap.Ec256: 'P-256',
    ap.Ec384: 'P-384',
    ap.Ec512: 'P-521',  # not a typo!
}
ED_ALG = {
    ap.Ed25519: 'ED25519',
    ap.Ed448: 'ED448',
}
RSA_PSS_PARAMS = {
    ap.RsaPss256: ('sha256', '32'),
    ap.RsaPss384: ('sha384', '48'),
    ap.RsaPss512: ('sha512', '64'),
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

    def generate_key_pair(self, alg_params: ap.BaseAlgParams) -> PrivateKey:
        gpk = []
        apcls = type(alg_params)

        if apcls in EC_CURVE:
            gpk.extend([
                '-algorithm', 'EC',
                '-pkeyopt', f'ec_paramgen_curve:{EC_CURVE[apcls]}',
                '-pkeyopt', 'ec_param_enc:named_curve'])

        elif apcls in ED_ALG:
            gpk.extend(['-algorithm', ED_ALG[apcls]])

        elif (
            issubclass(apcls, ap.BaseRsaParams)
            # second check isn't really necessary, fooling mypy
            and isinstance(alg_params, ap.BaseRsaParams)
        ):
            gpk.extend([
                '-algorithm', (
                    'RSA-PSS' if apcls in RSA_PSS_PARAMS else 'RSA'),
                '-pkeyopt', f'rsa_keygen_bits:{alg_params.bits}',
                '-pkeyopt', f'rsa_keygen_primes:{alg_params.primes}',
                '-pkeyopt', f'rsa_keygen_pubexp:{alg_params.pubexp}'])
            if apcls in RSA_PSS_PARAMS:
                h, salt = RSA_PSS_PARAMS[apcls]
                gpk.extend([
                    '-pkeyopt', f'rsa_pss_keygen_md:{h}',
                    '-pkeyopt', f'rsa_pss_keygen_mgf1_md:{h}',
                    '-pkeyopt', f'rsa_pss_keygen_saltlen:{salt}'])

        else:
            raise ValueError('Unsupported alg_params')

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
            crv = single_line_sections['NIST CURVE']
            if crv not in ('P-256', 'P-384', 'P-521'):
                raise ValueError(f'Bad EC curve: {crv}')
            return EcJsonWebPubKey(
                crv=cast(Literal['P-256', 'P-384', 'P-521'], crv),
                x=pub[:half],
                y=pub[half:])

        if (
            'Private-Key' in single_line_sections
            and 'modulus' in hex_section_parts
            and 'publicExponent' in single_line_sections
        ):
            return RsaJsonWebPubKey(
                n=b''.join(hex_section_parts['modulus']),
                e=int(single_line_sections['publicExponent'].split(' ', 1)[0]))

        if (
            'ED25519 Private-Key' in single_line_sections
            and 'priv' in hex_section_parts
        ):
            return EdJsonWebPubKey(
                crv='Ed25519',
                x=b''.join(hex_section_parts['priv']))

        if (
            'ED448 Private-Key' in single_line_sections
            and 'priv' in hex_section_parts
        ):
            return EdJsonWebPubKey(
                crv='Ed448',
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
        alg_params: ap.BaseAlgParams,
        key_pair: PrivateKey,
        data: bytes,
    ) -> bytes:
        cmd = []
        if (h := HASH_BY_ALG.get(alg_params.get_jws_alg(), None)):
            cmd.append(h)
        if alg_params.get_jws_alg().startswith('PS'):
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
                    case 'P-256':
                        s = 32
                    case 'P-384':
                        s = 48
                    case 'P-521':
                        s = 66
                    case _:
                        raise ValueError
                p1 = p1.rjust(s, b'\0')
                p2 = p2.rjust(s, b'\0')
                return p1 + p2
            case RsaJsonWebPubKey() | EdJsonWebPubKey():
                return signature
        raise ValueError

    def generate_csr(
        self,
        alg_params: ap.BaseAlgParams,
        key_pair: PrivateKey,
        domains: tuple[str, ...],
    ) -> bytes:
        cmd = []
        if (h := HASH_BY_ALG.get(alg_params.get_jws_alg(), None)):
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
