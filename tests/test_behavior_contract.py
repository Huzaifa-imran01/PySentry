
import hashlib
import runpy
from pathlib import Path

import pytest

from src.verifier import stage_candidate


SOURCE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "insecure_sample.py"
)

# Manually reviewed demonstration replacement.
# Never substitute arbitrary LLM output here.
REPLACEMENT = """
def evaluate_expression(user_input):
    import ast
    return ast.literal_eval(user_input)
""".strip()


@pytest.fixture
def literal_parser():
    """Load the trusted staged replacement for behavior testing."""

    fingerprint = hashlib.sha256(
        SOURCE.read_bytes()
    ).hexdigest()

    with stage_candidate(
        SOURCE,
        "evaluate_expression",
        REPLACEMENT,
        fingerprint,
    ) as candidate:

        namespace = runpy.run_path(str(candidate))

        yield namespace["evaluate_expression"]


@pytest.mark.parametrize(
    "input_text, expected",
    [
        ("42", 42),
        ("[1, 2, 3]", [1, 2, 3]),
        ("'hello'", "hello"),
    ],
)
def test_expected_literal_behavior(
    literal_parser,
    input_text,
    expected,
):
    """Valid literal inputs should still work."""

    assert literal_parser(input_text) == expected


def test_arithmetic_expression_rejected(literal_parser):
    """Arithmetic is outside this fixture's intended behavior."""

    with pytest.raises((ValueError, SyntaxError)):
        literal_parser("2 + 3")


def test_function_calls_rejected(literal_parser):
    """Function calls must not be evaluated."""

    with pytest.raises((ValueError, SyntaxError)):
        literal_parser("__import__('os').getcwd()")
