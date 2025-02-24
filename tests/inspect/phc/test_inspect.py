import pytest

from libpass.inspect.phc import PHC, inspect_phc
from libpass.inspect.phc.defs import Argon2PHC, BcryptSHA256PHCV2

_DEFINITIONS = (
    Argon2PHC,
    BcryptSHA256PHCV2,
)


@pytest.mark.parametrize(
    ("hash", "expected_type"),
    [
        (
            "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
            Argon2PHC,
        ),
        (
            "$bcrypt-sha256$v=2,t=2b,r=5$E/e/2AOhqM5W/KJTFQzLce$WFPIZKtDDTriqWwlmRFfHiOTeheAZWe",
            BcryptSHA256PHCV2,
        ),
    ],
)
def test_inspect_multiple_definitions(hash: str, expected_type: type[PHC]) -> None:
    result = inspect_phc(hash=hash, definition=_DEFINITIONS)
    assert isinstance(result, expected_type)
