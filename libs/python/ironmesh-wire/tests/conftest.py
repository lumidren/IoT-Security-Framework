"""Pytest fixtures: fixed test keys, identities, resolver and replay store."""

from __future__ import annotations

import pytest

from ironmesh_wire import envelope, vectors
from tests.helpers import KEYS_DIR


@pytest.fixture(scope="session")
def keys() -> vectors.TestKeys:
    return vectors.TestKeys.load(KEYS_DIR)


@pytest.fixture
def device_identity(keys: vectors.TestKeys) -> envelope.SigningIdentity:
    return keys.device_identity


@pytest.fixture
def tenant_identity(keys: vectors.TestKeys) -> envelope.SigningIdentity:
    return keys.tenant_identity


@pytest.fixture
def resolver(keys: vectors.TestKeys) -> envelope.StaticKeyResolver:
    return keys.resolver()


@pytest.fixture
def store() -> envelope.InMemoryReplayStore:
    return envelope.InMemoryReplayStore()
