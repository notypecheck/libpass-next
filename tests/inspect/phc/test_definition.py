import pytest

from libpass.inspect.phc import PHC, inspect_phc


def test_invalid_id() -> None:
    class MyPHC(PHC):
        id: str = "abc"

    with pytest.raises(ValueError) as exc_info:  # noqa: PT011
        inspect_phc(
            hash="$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
            definition=MyPHC,
        )

    assert str(exc_info.value) == "MyPHC.id field must be a Literal"
