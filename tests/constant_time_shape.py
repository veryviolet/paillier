"""The cache-address channel is guarded HERE, and only here.

The other two channels are guarded by measurement: `tests/timing_channel.rs`
fits a slope of time against the secret and fails if it is not flat. That
technique cannot work for this one. An address channel does not change
the answer or the time in any way a test can fit — reading one entry and
reading all sixty-four produce identical output, and the difference in
cost was measured at 1–5 %, which is inside the run-to-run noise of the
slope tests themselves.

So what is checked is the SHAPE of the code: that `select_entry` never
derives a memory address from the secret digit. That was verified to be
necessary — an adversarial review reverted the function to

    let start = digit as usize * width;
    out.copy_from_slice(&row[start..start + width]);

and the entire Rust and Python suite stayed green, position slope 1.578,
under the 2.5 limit.

Be clear about what this buys. It is a source-level check: renaming the
parameter evades it. It is not a proof of constant time; it is a tripwire
on the exact regression, in a twelve-line function whose whole purpose is
to have this shape. The alternative was a comment asking the next reader
to be careful.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAST = ROOT / "src" / "fast.rs"


def body_of(name):
    """The body of a top-level `fn`, by brace counting from its signature.

    Not a regex over the whole file: a regex that stops at the first `}`
    would read three lines of a twelve-line function and pass on anything
    below them.
    """
    source = FAST.read_text(encoding="utf-8")
    start = source.index(f"fn {name}(")
    opening = source.index("{", start)
    depth = 0
    for offset in range(opening, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[opening : offset + 1]
    raise AssertionError(f"fn {name} has no matching closing brace")


def code_lines(body):
    """Statements only — a comment mentioning `digit` is not an access."""
    out = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        out.append(stripped)
    return out


def test_there_is_a_function_to_check():
    """Otherwise the test below passes on an empty body.

    If `select_entry` is renamed or inlined, `body_of` raises and this
    fails first, which is the intended outcome: the guard must not
    silently stop guarding.
    """
    body = body_of("select_entry")

    assert len(code_lines(body)) >= 8, (
        f"select_entry has {len(code_lines(body))} statements — either it was "
        f"rewritten or the parser is broken"
    )


def test_the_secret_digit_never_reaches_an_address():
    """Every use of `digit` must be in the mask arithmetic.

    The mask is computed from `entry ^ digit`, so a line touching `digit`
    is fine if it also contains the xor. A line like
    `let start = digit as usize * width;` has no `^` and fails here.

    A plain binding with no indexing is allowed too — `let wanted = digit
    as u32;` hoisted above the loop, or an extracted `fn mask_for(entry,
    digit)`. Both are constant time and both are things a reader may
    reasonably want; rejecting them made this guard a nuisance rather
    than a check. What is never allowed is `digit` inside a `[…]`.
    """
    body = body_of("select_entry")

    offending = [
        line
        for line in code_lines(body)
        if re.search(r"\bdigit\b", line)
        and "^" not in line
        and ("[" in line or not line.startswith("let "))
    ]

    assert not offending, (
        "the secret digit is used outside the mask arithmetic in "
        f"select_entry: {offending}. If the address of a read depends on "
        "the digit, a process sharing the cache learns the exponent"
    )


def test_the_whole_row_is_traversed():
    """The loop must run over every entry, not over a selected one.

    Two forms are accepted, because both are constant time and a reader
    is entitled to prefer either: an explicit `0..ROW_ENTRIES`, or
    `chunks_exact(width)`, which removes the manual `entry * width`
    slicing. Rejecting the second was making this guard a nuisance rather
    than a check.
    """
    body = body_of("select_entry")

    assert re.search(r"0\.\.ROW_ENTRIES", body) or "chunks_exact" in body, (
        "select_entry no longer iterates over the whole row: its loop "
        "bound is neither the entry count nor an exact chunking"
    )


def test_the_loop_body_runs_for_every_entry():
    """Traversing the whole row is not enough — the body must not stop.

    This is the evasion the check above misses, and it was demonstrated:
    adding

        if is_wanted == 1 { break; }

    to the end of the loop passes every shape check, both slope tests and
    every functional test, while restoring the address dependency AND
    adding a trip count that depends on the secret digit.

    An early exit is exactly what a well-meaning optimisation looks like
    here, which is why the check is on the control flow rather than on
    the arithmetic.
    """
    body = body_of("select_entry")

    escapes = [
        line
        for line in code_lines(body)
        if re.search(r"\b(break|continue|return)\b", line)
    ]

    assert not escapes, (
        f"select_entry can leave its loop early: {escapes}. Then the number "
        f"of entries touched depends on the secret digit, which is the "
        f"channel this function exists to close"
    )


def test_the_conditional_subtraction_is_branch_free():
    """`Montgomery::mul` must end in `mpn_cnd_sub_n`, not in an `if`.

    Replacing

        mpn_cnd_sub_n(condition, out, out, modulus, k)

    with `if condition != 0 { mpn_sub_n(...) }` is arithmetically
    identical: all 38 Rust and 117 Python tests pass, both slope tests
    see nothing, and the count of `unsafe` GMP calls stays at four, so
    every claim in NOTICE.md and the module header remains literally
    true. What changes is that the last step of every multiplication
    branches on data derived from the secret exponent — which that step's
    own comment calls the classic way to lose constant time.

    Found by an adversarial review AFTER the same class of gap had been
    closed in `select_entry`, one file over. It is the more likely
    regression of the two, because `mpn_cnd_sub_n` reads as a needless
    complication to anyone who does not know why it is there.
    """
    mont = (ROOT / "src" / "mont.rs").read_text(encoding="utf-8")
    start = mont.index("pub fn mul(")
    opening = mont.index("{", start)
    depth = 0
    body = None
    for offset in range(opening, len(mont)):
        if mont[offset] == "{":
            depth += 1
        elif mont[offset] == "}":
            depth -= 1
            if depth == 0:
                body = mont[opening : offset + 1]
                break
    assert body, "Montgomery::mul has no matching closing brace"

    assert "mpn_cnd_sub_n" in body, (
        "Montgomery::mul no longer ends in mpn_cnd_sub_n. If the final "
        "subtraction became conditional on a branch, the last step of every "
        "multiplication now depends on the secret"
    )

    # The borrow is learnt, then the subtraction happens. Nothing may
    # branch between them.
    after_borrow = body[body.index("mpn_sub_n") :]
    branching = [
        line
        for line in code_lines(after_borrow)
        if re.match(r"^(if|match)\b", line) or re.search(r"\belse\b", line)
    ]

    assert not branching, (
        f"a branch stands between the borrow and the subtraction: {branching}. "
        f"The condition must be applied by mpn_cnd_sub_n, which subtracts "
        f"under a flag without branching"
    )
