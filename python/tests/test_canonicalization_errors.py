"""Canonicalization failures must arrive as a ``SeamError``, never as a bare builtin.

WHY THIS IS A FAIL-OPEN AND NOT A TIDINESS QUESTION
---------------------------------------------------
`seam-sdk#60 <https://github.com/zer07labs/seam-sdk/issues/60>`_, via
`seam-adapters#59 <https://github.com/zer07labs/seam-adapters/issues/59>`_. A consumer classifies
``SeamError`` as policy and everything else as transport. A builtin escaping an SDK call is
indistinguishable from a bug in the consumer's own code, so it lands in the generic arm that treats
failures as *availability* — and under ``FAIL_OPEN`` an availability failure runs the gated tool with
**zero RPCs sent**. Naming the failure is what lets a consumer route it as an input error instead.

The failures that matter here are mostly **not ones this SDK raises**. JCS reads caller-supplied
values through overridable dunders — ``__iter__`` on a container and on a ``str``, ``encode`` in the
key sort — so a hostile or concurrently-mutated input raises from CPython or from the caller's own
code, arbitrarily. ``RuntimeError: dictionary changed size during iteration`` is the motivating case
and is not something ``crypto.py`` could ever have raised deliberately. That is why the wrap is broad
and why its two exclusions (``BaseException`` out, an in-flight ``CanonicalizationError`` untouched)
are each pinned by their own test below.

Run: `python -m pytest python/tests/test_canonicalization_errors.py -q`
"""

from __future__ import annotations

import sys

import pytest

import seam_sdk
from seam_sdk import canonicalize_tool_input
from seam_sdk._authorize import build_authorize_request
from seam_sdk.crypto import jcs_canonicalize
from seam_sdk.errors import CanonicalizationError, SeamError

#: Everything `jcs_canonicalize` refuses on its own, with the builtin each one used to raise. The
#: pairing is the compatibility assertion: after this change they are still caught by the same
#: `except` clause a consumer wrote before it.
REJECTED = [
    pytest.param(float("nan"), ValueError, id="nan"),
    pytest.param(float("inf"), ValueError, id="inf"),
    pytest.param(2**53 + 1, ValueError, id="int-jcs-cannot-render"),
    pytest.param({1: "non-string key"}, TypeError, id="non-string-key"),
    pytest.param(object(), TypeError, id="unserializable"),
    pytest.param({"s": "\ud800"}, ValueError, id="lone-surrogate-at-encode"),
]

ACCEPTED = [
    None,
    {},
    {"a": 1},
    [1, "two", None, True],
    {"z": 1, "a": {"n": [1.5]}},
    "s",
    1e16,
]


# ── the taxonomy ─────────────────────────────────────────────────────────────────────────────────


def test_canonicalization_error_is_all_three_bases() -> None:
    """The triple base is the entire compatibility story, so it is asserted directly rather than
    inferred from the behaviour tests below."""
    for base in (SeamError, ValueError, TypeError):
        assert issubclass(CanonicalizationError, base), (
            f"CanonicalizationError lost its {base.__name__} base. Existing callers wrote "
            f"`except {base.__name__}` around a canonicalizing call and would now stop catching it — "
            f"which turns an additive change into a breaking one."
        )


def test_it_is_exported_from_the_package_root() -> None:
    assert seam_sdk.CanonicalizationError is CanonicalizationError
    assert "CanonicalizationError" in seam_sdk.__all__
    assert "canonicalize_tool_input" in seam_sdk.__all__


# ── the helper agrees with the primitive, and only differs in how it fails ───────────────────────


@pytest.mark.parametrize("value", ACCEPTED, ids=lambda v: repr(v)[:24])
def test_accepted_inputs_produce_identical_bytes(value) -> None:
    """The helper must not be a second canonicalization with its own opinions — that is the very
    defect #60 is about. For anything accepted it is `jcs_canonicalize`, byte for byte."""
    assert canonicalize_tool_input(value) == jcs_canonicalize(
        value if value is not None else {}
    )


@pytest.mark.parametrize(("value", "legacy"), REJECTED)
def test_rejected_inputs_raise_the_typed_error_and_stay_catchable(
    value, legacy
) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_tool_input(value)
    # The half that proves this is additive: the pre-existing `except` clause still fires.
    with pytest.raises(legacy):
        canonicalize_tool_input(value)


def test_build_authorize_request_raises_typed_not_builtin() -> None:
    """The public path, not just the helper — this is where a consumer actually meets it."""
    with pytest.raises(CanonicalizationError):
        build_authorize_request(
            ticket=b"t", agent_seed=bytes(32), tool_name="x", tool_input=object()
        )


# ── failures raised by the CALLER's code, which is the whole point ───────────────────────────────


class _MutatingDict(dict):
    """Stands in for a container mutated by another thread mid-canonicalization.

    Raising from ``__iter__`` rather than mutating from a real thread is deliberate: the defect is
    that *a builtin escapes*, and a live race would make this test flaky while proving the same
    thing. `RuntimeError` is the exact type CPython raises for `dictionary changed size during
    iteration`, and it is not in `ValueError`/`TypeError` — so before this change it escaped even a
    caller who had thought to catch both.
    """

    def __iter__(self):
        raise RuntimeError("dictionary changed size during iteration")


class _FlakyKey(str):
    """A ``str`` subclass that answers the key sort and then raises when JCS reads it again.

    JCS reads a dict key twice — ``encode("utf-16-be")`` for the UTF-16 code-unit sort, then
    character-by-character to escape it. Frameworks ship ``str`` subclasses for units, tainted
    strings and lazy i18n; one that is not stable across two reads is enough.
    """

    def __iter__(self):
        raise RuntimeError("second read disagrees with the first")


class _Interrupting(dict):
    def __iter__(self):
        raise KeyboardInterrupt


class _AlreadyTyped(dict):
    def __iter__(self):
        raise CanonicalizationError("raised from inside the traversal")


def test_a_mutating_container_surfaces_typed_with_the_cause_kept() -> None:
    with pytest.raises(CanonicalizationError) as exc:
        canonicalize_tool_input(_MutatingDict(a=1))
    assert isinstance(exc.value.__cause__, RuntimeError), (
        "the original must survive as __cause__ — it is the only thing that keeps a genuine SDK bug "
        "diagnosable once it has been typed as an input error"
    )


def test_an_unstable_string_subclass_surfaces_typed() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_tool_input({_FlakyKey("a"): 1})


def test_recursion_depth_surfaces_typed() -> None:
    """A `RecursionError` is an input error from the caller's side, so it is caught — and it must be
    caught *after* the stack unwinds, or building the replacement exception re-triggers it."""
    deep = []
    for _ in range(sys.getrecursionlimit() * 3):
        deep = [deep]
    with pytest.raises(CanonicalizationError):
        canonicalize_tool_input(deep)


def test_base_exception_still_propagates() -> None:
    """`except Exception`, not `except BaseException` — a Ctrl-C during canonicalization must stay a
    Ctrl-C. Catching it would make the SDK unkillable mid-call and would report a user interrupt as
    a malformed tool input."""
    with pytest.raises(KeyboardInterrupt):
        canonicalize_tool_input(_Interrupting(a=1))


def test_an_already_typed_error_is_not_double_wrapped() -> None:
    """Re-wrapping would bury the real cause one level deeper on every layer it passes through, and
    Phase 4's `canonical=` validation raises this type from inside the same call."""
    with pytest.raises(CanonicalizationError) as exc:
        canonicalize_tool_input(_AlreadyTyped(a=1))
    assert exc.value.__cause__ is None
    assert str(exc.value) == "raised from inside the traversal"
