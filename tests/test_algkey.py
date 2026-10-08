import pytest

from acmeerkat import (
    Algorithm, EcKeyParams, EcType,
    EdKeyParams, EdVariant,
    RsaKeyParams, RsaPssKeyParams)
from acmeerkat.core import _check_alg_key_params


@pytest.mark.parametrize('key_params,valid_algs', [
    (
        EcKeyParams(crv=EcType.P_256),
        [Algorithm.ES256]),
    (
        EcKeyParams(crv=EcType.P_384),
        [Algorithm.ES384]),
    (
        EcKeyParams(crv=EcType.P_521),
        [Algorithm.ES512]),
    (
        EdKeyParams(crv=EdVariant.Ed25519),
        [Algorithm.EdDSA]),
    (
        EdKeyParams(crv=EdVariant.Ed448),
        [Algorithm.EdDSA]),
    (
        RsaKeyParams(),
        [Algorithm.RS256, Algorithm.RS384, Algorithm.RS512]),
    (
        RsaPssKeyParams(alg=Algorithm.PS256),
        [Algorithm.PS256]),
    (
        RsaPssKeyParams(alg=Algorithm.PS384),
        [Algorithm.PS384]),
    (
        RsaPssKeyParams(alg=Algorithm.PS512),
        [Algorithm.PS512]),
])
def test_check_alg_key_params(key_params, valid_algs):
    for alg in Algorithm:
        if alg in valid_algs:
            _check_alg_key_params(alg, key_params)
        else:
            with pytest.raises(ValueError):
                _check_alg_key_params(alg, key_params)
