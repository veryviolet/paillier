"""Re-randomisation: the same plaintext, different bytes.

The homomorphic operations here are deterministic — `add_many` of the
same terms gives the same bytes, a one-term sum gives its input back
verbatim, and `multiply_many` gives exactly `E(x)^k`. Anyone who knows
the inputs can therefore confirm a guess about the operation by
recomputing it: which terms went into a sum, or what the scalar was.

`rerandomize` is what a caller applies before the result leaves. The
tests below check both halves of the contract — the bytes must change and
the value must not — because either alone is satisfied by something
broken: multiplying by a random element of the group changes the bytes
and destroys the value, and returning the input keeps the value and
changes nothing.
"""
import pytest

import paillier as p

BITS = 2048


@pytest.fixture(scope="module")
def key():
    return p.generate_keypair(BITS)


def one(pub, value, **kw):
    return bytes(list(p.encrypt_many(pub, [value], **kw))[0])


def test_the_bytes_change(key):
    pub, _ = key
    blob = one(pub, 42.5)

    again = bytes(p.rerandomize(pub, [blob])[0])

    assert again != blob


def test_the_value_does_not(key):
    """Without this, the test above passes on multiplication by any
    random group element — which changes the bytes and destroys the
    plaintext."""
    pub, sec = key
    blob = one(pub, -17.25)

    again = bytes(p.rerandomize(pub, [blob])[0])

    assert p.decrypt(sec, again) == pytest.approx(-17.25, abs=1e-7)


def test_twice_gives_two_different_ciphertexts(key):
    """A cached or reused `r` would pass both tests above."""
    pub, sec = key
    blob = one(pub, 3.5)

    first = bytes(p.rerandomize(pub, [blob])[0])
    second = bytes(p.rerandomize(pub, [blob])[0])

    assert first != second
    assert p.decrypt(sec, first) == pytest.approx(3.5, abs=1e-7)
    assert p.decrypt(sec, second) == pytest.approx(3.5, abs=1e-7)


def test_duplicates_in_one_batch_differ(key):
    """Hoisting the exponentiation out of the loop — one `r` shared
    across the batch — is the obvious optimisation, and it would leak
    that two ciphertexts were equal."""
    pub, _ = key
    blob = one(pub, 8.0)

    first, second = [bytes(b) for b in p.rerandomize(pub, [blob, blob])]

    assert first != second


def test_the_scale_byte_is_untouched(key):
    """Re-randomising is not an arithmetic operation and must not look
    like one: an altered scale byte would silently rescale the value."""
    pub, sec = key
    blob = one(pub, 2.0, scale_pow10=12)
    assert blob[0] == 12

    again = bytes(p.rerandomize(pub, [blob])[0])

    assert again[0] == 12
    assert p.decrypt(sec, again) == pytest.approx(2.0, abs=1e-11)


def test_it_closes_the_sum_recomputation_check(key):
    """The threat, stated as the threat.

    A party that supplied the terms can recompute their sum and compare
    it with what came back. That check succeeds against a raw
    `add_many` and must fail against a re-randomised one — while the
    sum still decrypts to the same number.
    """
    pub, sec = key
    terms = [bytes(b) for b in p.encrypt_many(pub, [1.0, 2.0, 3.0])]

    raw = bytes(p.add_many(pub, terms))
    guarded = bytes(p.rerandomize(pub, [raw])[0])

    # What the supplier of the terms would recompute.
    recomputed = bytes(p.add_many(pub, terms))

    assert recomputed == raw, (
        "add_many stopped being deterministic - then this test is no "
        "longer about what it says it is about"
    )
    assert recomputed != guarded
    assert p.decrypt(sec, guarded) == pytest.approx(6.0, abs=1e-7)


def test_it_closes_the_scalar_recomputation_check(key):
    """The same for a product: `E(x)^k` is recomputable by anyone holding
    `E(x)` and a guess at `k`."""
    pub, sec = key
    blob = one(pub, 4.0)

    product = bytes(p.multiply_many(pub, [blob], [-2.5])[0])
    guarded = bytes(p.rerandomize(pub, [product])[0])

    guessed = bytes(p.multiply_many(pub, [blob], [-2.5])[0])

    assert guessed == product, (
        "multiply_many stopped being deterministic - then this test is no "
        "longer about what it says it is about"
    )
    assert guessed != guarded
    assert p.decrypt(sec, guarded) == pytest.approx(-10.0, abs=1e-6)


def test_a_batch_keeps_its_order(key):
    """Results are paired with the input by position, and a shuffle would
    be invisible to every test that looks at one element."""
    pub, sec = key
    values = [1.0, -2.0, 30.0, 0.5]
    blobs = [one(pub, v) for v in values]

    again = p.rerandomize(pub, blobs)

    for value, blob in zip(values, again):
        assert p.decrypt(sec, bytes(blob)) == pytest.approx(value, abs=1e-7)


def test_an_empty_batch_is_an_empty_result(key):
    pub, _ = key

    assert list(p.rerandomize(pub, [])) == []


def test_a_bad_ciphertext_is_refused(key):
    """`PanicException` inherits `BaseException` and would pass through
    the caller's `except Exception`."""
    pub, _ = key

    with pytest.raises(ValueError):
        p.rerandomize(pub, [b""])
    with pytest.raises(ValueError):
        p.rerandomize(pub, [b"\x08\x00"])


def test_the_peer_key_can_rerandomize(key):
    """The side that only encrypts holds `n` alone — and it is the side
    that sends results back."""
    pub, sec = key
    peer = p.PublicKey.from_n(pub.modulus_bytes())
    blob = one(peer, 6.0)

    again = bytes(p.rerandomize(peer, [blob])[0])

    assert again != blob
    assert p.decrypt(sec, again) == pytest.approx(6.0, abs=1e-7)


def test_the_masking_exponent_is_full_width(key):
    """The exponent must be as WIDE as an encryption's. Not as random —
    that cannot be measured from here, and the docstring used to claim it
    could.

    A re-randomisation costs about one encryption because it is one
    exponentiation of the same width, so a narrower buffer shows up as a
    smaller ratio. What does NOT show up is a full-width buffer with only
    its first bytes drawn: same width, same cost, thirty-two bits of
    entropy. A review broke it exactly that way and all twelve tests here
    passed.

    No TIMING measurement closes that gap. `pow_by_table` reads every row
    in full and multiplies at every window precisely so that the digit
    values do not affect the cost.

    A black-box collision test would catch the catastrophic case —
    re-randomise one blob `2^18` times and look for a duplicate — but
    only that case, and it is not what a suite should rest on. Entropy is
    held structurally instead: one `random_exponent` shared with
    `encrypt_many`, guarded by `the_whole_exponent_is_drawn` in the Rust
    tests, which checks the bytes per position.

    The criterion here is the ratio to an encryption on the same machine,
    not an absolute time.
    """
    import statistics
    import time

    pub, _ = key
    blob = one(pub, 1.0)

    def median_seconds(action):
        action()
        taken = []
        for _ in range(7):
            started = time.perf_counter()
            for _ in range(5):
                action()
            taken.append((time.perf_counter() - started) / 5)
        return statistics.median(taken)

    encrypting = median_seconds(lambda: p.encrypt_many(pub, [1.0]))
    masking = median_seconds(lambda: p.rerandomize(pub, [blob]))
    ratio = masking / encrypting
    print(f"encrypt {encrypting * 1e6:.1f} us, rerandomize "
          f"{masking * 1e6:.1f} us, ratio {ratio:.2f}")

    assert ratio > 0.5, (
        f"re-randomising costs {ratio:.2f} of an encryption: it should cost "
        f"about one exponentiation of the SAME width. A narrow masking "
        f"exponent is cheap, and cheap here means brute-forceable"
    )
