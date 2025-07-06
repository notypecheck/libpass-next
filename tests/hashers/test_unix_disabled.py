import uuid

import pytest

from libpass.hashers.unix_disabled import UnixDisabled


@pytest.fixture
def hasher() -> UnixDisabled:
    return UnixDisabled()


def test_hash(hasher: UnixDisabled) -> None:
    assert hasher.hash(str(uuid.uuid4())) == hasher.prefix


def test_disable(hasher: UnixDisabled) -> None:
    hash = str(uuid.uuid4())
    assert hasher.disable(hash) == hasher.prefix + hash


def test_disable_already_disabled(hasher: UnixDisabled) -> None:
    disabled = hasher.prefix + str(uuid.uuid4())
    assert hasher.disable(disabled) == disabled


def test_enable(hasher: UnixDisabled) -> None:
    hash = str(uuid.uuid4())
    disabled = hasher.prefix + hash
    assert hasher.enable(disabled) == hash


def test_enable_enabled(hasher: UnixDisabled) -> None:
    hash = str(uuid.uuid4())
    assert hasher.enable(hash) == hash


def test_roundtrip(hasher: UnixDisabled) -> None:
    hash = str(uuid.uuid4())

    disabled = hasher.disable(hash)
    assert hasher.enable(disabled) == hash


def test_needs_update(hasher: UnixDisabled) -> None:
    hash = str(uuid.uuid4())
    assert not hasher.needs_update(hash)
    assert not hasher.needs_update(hasher.disable(hash))


@pytest.mark.parametrize(
    "hash",
    [
        "hash",
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
        "!",
        "",
    ],
)
def test_verify(hash: str, hasher: UnixDisabled) -> None:
    assert not hasher.verify(hash, secret=hash)
    assert not hasher.verify(hasher.disable(hash), secret=hash)
