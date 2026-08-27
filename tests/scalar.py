"""Multiplication of a ciphertext by a KNOWN scalar.

`E(x)^k = E(k·x)` is what an additively homomorphic scheme gives for
free, and it is what lets a party compute a squared distance between two
distributions without showing either. Without it a caller has to fall
back on a library that has it, which is how this one came to be needed.

Three things are checked, and only the first is arithmetic:

* the product decrypts to `k·x`, across signs and magnitudes;
* the SCALE of the product is handled by the library rather than by the
  caller. The product lands at the sum of the two scales, and the
  `phe`-based code this replaces returned it with the original scale byte
  and a docstring saying "the caller must divide";
* the refusals. A scalar that encodes to zero destroys the value and
  produces a recognisable constant; one past the fixed exponent width
  would make the timing depend on its magnitude.
"""
import math

import pytest

import paillier as p

BITS = 2048


@pytest.fixture(scope="module")
def key():
    return p.generate_keypair(BITS)


def one(pub, value, **kw):
    return bytes(list(p.encrypt_many(pub, [value], **kw))[0])


def scale_of(blob):
    """The scale exponent is the first byte of the blob."""
    return blob[0]


@pytest.mark.parametrize("value,scalar", [
    (3.0, 2.0),
    (3.0, -2.0),
    (-3.0, 2.0),
    (-3.0, -2.0),
    (1.5, 0.25),
    (1234.5, 1.0),
    (0.0, 7.0),
    (7.25, 0.001),
])
def test_the_product_decrypts_to_the_product(key, value, scalar):
    pub, sec = key

    got = bytes(p.multiply_many(pub, [one(pub, value)], [scalar])[0])

    assert p.decrypt(sec, got) == pytest.approx(value * scalar, abs=1e-6)


def test_the_scale_of_the_product_is_the_sum_of_the_two(key):
    """And it is READ FROM THE BLOB, not agreed by convention."""
    pub, _ = key
    blob = one(pub, 2.0)
    assert scale_of(blob) == 8

    product = bytes(p.multiply_many(pub, [blob], [3.0])[0])

    assert scale_of(product) == 16


def test_the_scalar_scale_can_be_lowered(key):
    """Which is what makes chaining possible at all — see the refusal
    test below."""
    pub, sec = key
    blob = one(pub, 2.0)

    product = bytes(
        p.multiply_many(pub, [blob], [3.0], scalar_scale_pow10=4)[0]
    )

    assert scale_of(product) == 12
    assert p.decrypt(sec, product) == pytest.approx(6.0, abs=1e-6)


def test_a_product_adds_to_a_companion_at_the_same_scale(key):
    """The scenario this feature exists for, in miniature.

    `add_many` refuses a mixed batch, so the companion has to be
    encrypted at the product's scale. That is the whole contract: the
    caller states the scale once, at encryption, instead of dividing
    afterwards and hoping to remember.
    """
    pub, sec = key
    product = bytes(p.multiply_many(pub, [one(pub, 4.0)], [-2.0])[0])
    companion = one(pub, 1.0, scale_pow10=16)

    total = p.add_many(pub, [product, companion])

    assert p.decrypt(sec, total) == pytest.approx(-8.0 + 1.0, abs=1e-6)


def test_a_companion_at_the_wrong_scale_is_refused(key):
    """Otherwise the previous test's contract is a suggestion.

    This is the failure the `phe` version produced as a plausible number:
    a product at 1e16 summed with a value at 1e8 is off by a hundred
    million, finite, with nothing to notice.
    """
    pub, _ = key
    product = bytes(p.multiply_many(pub, [one(pub, 4.0)], [-2.0])[0])

    with pytest.raises(ValueError, match="scale"):
        p.add_many(pub, [product, one(pub, 1.0)])


def test_multiplication_does_not_compose_at_the_default(key):
    """A second multiplication is past the encoding, and it is a refusal
    rather than a silent truncation of the scale byte.

    The scalar scale DEFAULTS to the ciphertext's, so the second call is
    `16 + 16 = 32`, not `16 + 8`. That default is what makes chaining
    need the escape hatch below.
    """
    pub, _ = key
    product = bytes(p.multiply_many(pub, [one(pub, 2.0)], [3.0])[0])

    with pytest.raises(ValueError, match="1e32"):
        p.multiply_many(pub, [product], [2.0])


def test_it_composes_when_the_scalar_scale_is_lowered(key):
    """The escape hatch has to work, or the refusal above is a dead end."""
    pub, sec = key
    first = bytes(
        p.multiply_many(pub, [one(pub, 2.0)], [3.0], scalar_scale_pow10=2)[0]
    )
    second = bytes(
        p.multiply_many(pub, [first], [5.0], scalar_scale_pow10=2)[0]
    )

    assert scale_of(second) == 12
    assert p.decrypt(sec, second) == pytest.approx(30.0, abs=1e-6)


@pytest.mark.parametrize("scalar", [0.0, 1e-9, -1e-9])
def test_a_scalar_that_encodes_to_zero_is_refused(key, scalar):
    """`E(x)^0` is the constant 1: the value is gone and the result is a
    two-byte blob anyone can recognise.

    In the intended caller the scalar is a bucket share, so a vanishing
    one means an empty bucket — and a distinctive blob saying "this
    bucket is empty" is a leak, not a result.
    """
    pub, _ = key

    with pytest.raises(ValueError, match="zero"):
        p.multiply_many(pub, [one(pub, 5.0)], [scalar])


@pytest.mark.parametrize("scalar", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_scalar_is_refused(key, scalar):
    """Same rule as for values: no encoding exists, and a credible zero
    would travel onward."""
    pub, _ = key

    with pytest.raises(ValueError):
        p.multiply_many(pub, [one(pub, 5.0)], [scalar])


def test_a_scalar_past_the_fixed_width_is_refused(key):
    """The exponent width is a constant of the scheme, not a function of
    the scalar.

    A per-scalar width would show the scalar's magnitude in the timing,
    and the scalar is the secret this operation exists to keep. So a
    scalar that does not fit is refused rather than run at a wider
    exponent.
    """
    pub, _ = key
    # 2^64 / 1e8 is about 1.8e11; this is comfortably past it.
    with pytest.raises(ValueError, match="width"):
        p.multiply_many(pub, [one(pub, 1.0)], [1e13])


def test_lengths_must_match(key):
    """They are paired by position; a mismatch means the pairing that
    happens is not the one the caller intended."""
    pub, _ = key

    with pytest.raises(ValueError, match="scalars"):
        p.multiply_many(pub, [one(pub, 1.0), one(pub, 2.0)], [3.0])


def test_an_empty_batch_is_an_empty_result(key):
    """Nothing to refuse here: zero pairs is a well-defined request with
    a well-defined answer, unlike an empty SUM which has no encryption."""
    pub, _ = key

    assert list(p.multiply_many(pub, [], [])) == []


def test_a_batch_is_multiplied_elementwise(key):
    """The pairing is by position, and this is what pins it: three
    different scalars on three different values, all wrong if any pair
    slips.
    """
    pub, sec = key
    values = [2.0, -3.0, 0.5]
    scalars = [10.0, 2.0, -4.0]
    blobs = [one(pub, v) for v in values]

    products = p.multiply_many(pub, blobs, scalars)

    for value, scalar, product in zip(values, scalars, products):
        assert p.decrypt(sec, bytes(product)) == pytest.approx(
            value * scalar, abs=1e-6
        )


def test_a_bad_ciphertext_is_refused(key):
    """`PanicException` inherits `BaseException` and would pass through
    the caller's `except Exception`."""
    pub, _ = key

    with pytest.raises(ValueError):
        p.multiply_many(pub, [b"\x08\x00"], [2.0])


def test_the_peer_key_can_multiply(key):
    """The side that only encrypts holds `n` alone, and that is the side
    that multiplies by its own secret scalar."""
    pub, sec = key
    peer = p.PublicKey.from_n(pub.modulus_bytes())

    product = bytes(p.multiply_many(peer, [one(peer, 6.0)], [-0.5])[0])

    assert p.decrypt(sec, product) == pytest.approx(-3.0, abs=1e-6)


def test_the_exponent_width_does_not_depend_on_the_scalar(key):
    """The property the fixed width exists for, measured as a slope.

    A `secure_pow_mod` whose exponent is `k` itself runs in time
    proportional to the BIT LENGTH of `k` — and the bit length is the
    magnitude of the scalar, which is the secret. Here the exponent is
    offset to a constant width, so the time must not depend on `k`.

    The criterion is the slope against the scalar's bit length, not the
    absolute time: absolute time depends on the machine.
    """
    import random
    import statistics
    import time

    pub, _ = key
    blob = one(pub, 1.0)

    # Encoded at 1e8 these span 1 bit to about 37 bits.
    scalars = [1e-8, 1e-4, 1.0, 100.0, 1000.0]

    # INTERLEAVED, and shuffled within each round. Measuring the scalars
    # one after another in ascending order turns any monotone drift of
    # the machine — thermal, frequency scaling, a neighbouring process —
    # into slope, because the drift and the bit count both increase with
    # wall-clock time. Measured that way this test failed about one run
    # in four on an idle machine, with the sign flipping between runs,
    # which is what noise looks like and what a real leak does not.
    #
    # Interleaving does not reduce the noise; it stops it from being
    # correlated with the quantity under test, which is the only part
    # that matters for a slope.
    rounds = 25
    samples = {scalar: [] for scalar in scalars}
    for scalar in scalars:
        p.multiply_many(pub, [blob], [scalar])  # warm-up, all of them
    order = list(scalars)
    for _ in range(rounds):
        random.shuffle(order)
        for scalar in order:
            started = time.perf_counter()
            for _ in range(3):
                p.multiply_many(pub, [blob], [scalar])
            samples[scalar].append((time.perf_counter() - started) / 3)

    points = [
        (max(1, round(scalar * 1e8)).bit_length(),
         # MINIMUM, not median. What interference does is add time, never
         # subtract it, so the smallest sample is the one least
         # contaminated — the standard choice for a timing benchmark, and
         # the median still carried enough noise here to touch the
         # threshold two runs in ten.
         min(samples[scalar]))
        for scalar in scalars
    ]

    mean_x = sum(x for x, _ in points) / len(points)
    mean_y = sum(y for _, y in points) / len(points)
    top = sum((x - mean_x) * (y - mean_y) for x, y in points)
    bottom = sum((x - mean_x) ** 2 for x, _ in points)
    slope = top / bottom

    for bits, seconds in points:
        print(f"scalar of {bits:>3} bits   {seconds * 1e6:9.1f} us")
    print(f"slope: {slope * 1e6:.3f} us per bit of scalar")

    # Both sides of the threshold are measured, not chosen.
    #
    # SIGNAL. A `secure_pow_mod` on the raw `k` costs about one modular
    # multiplication per exponent bit — roughly 25 us at this modulus —
    # so a real magnitude leak shows up as a POSITIVE slope of that
    # order.
    #
    # NOISE. Interleaved and on the minimum statistic: ten runs here gave
    # −0.94 to −0.14, and a reviewer's six gave −0.20 to +1.04 —
    # including four under twelve-core contention, worse than any shared
    # CI runner, which stayed within −0.96. The band to record is the
    # worst anyone has seen, so it is +-1.1: the threshold sits 2.4x
    # above it and twenty times below the signal.
    #
    # For the record of how it got here: measured in ascending order on
    # medians, the same test spanned −5.4 to +2.6 and failed about one
    # run in four — the sign flipping, which is what noise looks like
    # and what a leak does not.
    assert abs(slope) * 1e6 < 2.5, (
        f"the time depends on the magnitude of the scalar: {slope * 1e6:.3f} "
        f"us per bit. The exponent is supposed to be offset to a constant "
        f"width precisely so that it does not"
    )


def test_the_product_is_not_the_input(key):
    """A `k = 1` fast path returning the input would pass every value
    check above.

    It is also the shape someone adds as an optimisation, so it is
    pinned: multiplying by one still produces a different blob, because
    the exponentiation is still performed.
    """
    pub, sec = key
    blob = one(pub, 5.0)

    product = bytes(p.multiply_many(pub, [blob], [1.0])[0])

    assert p.decrypt(sec, product) == pytest.approx(5.0, abs=1e-6)
    assert product != blob, (
        "multiplying by one returned the input unchanged - the scale byte "
        "alone should differ, and so should the ciphertext"
    )


def test_the_magnitude_bound_is_reachable(key):
    """The width refusal must not be so tight that ordinary scalars trip
    it, or the previous test proves only that everything is refused."""
    pub, sec = key
    # 1e10 at scale 1e8 encodes to 1e18, which is under 2^64 ≈ 1.8e19.
    product = bytes(p.multiply_many(pub, [one(pub, 2.0)], [1e10])[0])

    assert math.isclose(p.decrypt(sec, product), 2e10, rel_tol=1e-9)
