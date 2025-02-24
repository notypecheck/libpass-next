import math

import pytest

from libpass._utils.validation import validate_rounds


@pytest.mark.parametrize(
    ("min_rounds", "max_rounds", "value"),
    [
        (0, 100, -1),
        (0, 100, 101),
        (0, 100, -math.inf),
        (0, 100, math.inf),
    ],
)
def test_err(min_rounds: int, max_rounds: int, value: int) -> None:
    with pytest.raises(ValueError) as exc_info:  # noqa: PT011
        validate_rounds(min=min_rounds, max=max_rounds, rounds=value)
    assert str(exc_info.value) == f"rounds must be between {min_rounds} - {max_rounds}"


@pytest.mark.parametrize(
    ("min_rounds", "max_rounds", "value"),
    [
        (0, 0, 0),
        (0, 100, 100),
        (0, 100, 0),
    ],
)
def test_ok(min_rounds: int, max_rounds: int, value: int) -> None:
    validate_rounds(min=min_rounds, max=max_rounds, rounds=value)
