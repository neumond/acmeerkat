from dataclasses import dataclass
from typing import Any

import pytest

from acmeerkat.storage.k8s_secret import (
    serialize, KvBufReader, K8sSecretStorage, Kind)


@pytest.mark.parametrize('data', [
    {},
    {b'key': b'value'},
    {b'alpha': b'one', b'beta': b'two', b'gamma': b'three'},
    {b'': b'value'},
    {b'key': b''},
    {b'': b''},
    {
        b'\x00\x01\x02': b'\xff\xfe\xfd',
        bytes(range(256)): bytes(range(255, -1, -1))},
])
def test_serialize_roundtrip(data):
    assert KvBufReader(serialize(data)).read_kv() == data


def test_serialize_roundtrip_large_kv():
    data = {b'k' * 1_000_000: b'x' * 1_000_000}
    assert KvBufReader(serialize(data)).read_kv() == data


def test_deserialize_large():
    with pytest.raises(ValueError):
        KvBufReader(b'\xFF' * 12).read_kv()


@dataclass
class FakeApi:
    chart: dict[Any, Any] | None

    def upsert_object(
        self,
        kind: Kind,
        name: str,
        chart: dict[Any, Any],
        recreate: bool = False,
        namespace: str | None = None,
    ) -> dict[Any, Any]:
        assert kind is Kind.Secret
        assert name == 'test'
        assert namespace is None
        self.chart = chart
        return chart

    def get_object(
        self,
        kind: Kind,
        name: str,
        namespace: str | None = None,
    ) -> dict[Any, Any] | None:
        assert kind is Kind.Secret
        assert name == 'test'
        assert namespace is None
        return self.chart


def test_storage():
    fake_api = FakeApi(None)

    s = K8sSecretStorage(fake_api, 'test')
    s.update({b'abc': b'123'})

    s = K8sSecretStorage(fake_api, 'test')
    s.get(b'abc') == b'123'
