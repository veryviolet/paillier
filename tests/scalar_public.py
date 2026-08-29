"""Multiplication by a scalar the caller declares PUBLIC.

`multiply_many_public` computes what `multiply_many` computes and pays a
different price for it. The arithmetic is one windowed exponentiation
instead of two `secure_pow_mod` and an inversion; what is bought with the
saving is speed, and what is sold is the constancy of the timing.

Three things are checked here, and the third is the one that would
otherwise never be noticed:

* the two paths agree BYTE FOR BYTE, not "within tolerance". A
  homomorphic product is a deterministic function of the inputs, so any
  difference at all is a difference in the result;
* the refusals are the same refusals, including the one that only this
  path has — a scalar past `2^53`, where an `f64` stops holding every
  integer;
* the timing DOES depend on the scalar. That is the trade, and a test
  that only proved correctness would let someone "clean up" the fast path
  into a constant-width one — or the reverse — with nothing going red.

Reference vectors live at the bottom. Two nodes running different builds
of this library do not produce an error when they disagree; they produce
a plausible wrong number, and only a fixed expected value catches that.
"""
import pytest

import paillier as p

BITS = 2048


@pytest.fixture(scope="module")
def key():
    return p.generate_keypair(BITS)


def one(pub, value, **kw):
    return bytes(p.encrypt_many(pub, [value], **kw)[0])


# ---------------------------------------------------------------------
# The two paths agree
# ---------------------------------------------------------------------

SCALARS = [
    1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 7.25, -7.25,
    1e-8, -1e-8, 1844.0, -1844.0, 1000.5, 12345.0, 0.001,
]


#: Ciphertext scales to run the comparison at. The DEFAULT alone is not
#: enough and that is not a hypothetical: with only `cpow=8` in the
#: parametrisation, replacing `scalar_scale_pow10.unwrap_or(pow10)` with
#: `unwrap_or(DEFAULT_SCALE_POW10)` passed ten runs out of ten — at the
#: default the two expressions are the same expression. The same lesson
#: is written down in `scripts/smoke_wheel.py`.
#:
#: Capped at 9: with the scalar scale defaulting to the ciphertext's, the
#: product lands at `2·cpow`, and 2·9 = 18 is the encoding's ceiling.
#: Above that BOTH paths refuse — correctly — so a comparison there
#: compares two refusals and proves nothing about the arithmetic.
CIPHERTEXT_SCALES = [0, 4, 8, 9]


@pytest.mark.parametrize("cpow", CIPHERTEXT_SCALES)
@pytest.mark.parametrize("scalar", SCALARS)
def test_both_paths_produce_the_same_bytes(key, scalar, cpow):
    """Byte equality, not numeric closeness.

    Both are `E(x)^k` under the same modulus with no randomness in the
    operation, so equality is exact or the implementations differ.
    """
    pub, _ = key
    blob = one(pub, 3.5, scale_pow10=cpow)

    def outcome(fn):
        """Either the bytes, or the fact of refusal.

        Comparing only successes would skip the combinations where both
        refuse — and those are the majority at the low scales, where a
        small scalar encodes to zero. Refusals have to agree too: a pair
        of functions that computes the same thing but disagrees about
        what is admissible is still two different functions.
        """
        try:
            return ("ok", bytes(fn(pub, [blob], [scalar])[0]))
        except ValueError:
            return ("refused", None)

    secret = outcome(p.multiply_many)
    public = outcome(p.multiply_many_public)

    if secret[0] == "refused" and public[0] == "refused":
        return  # both refuse; agreement is the assertion

    assert secret == public, (
        f"paths diverged at k={scalar}, cpow={cpow}: "
        f"secret={secret[0]}, public={public[0]}"
    )


@pytest.mark.parametrize("cpow", [0, 4, 9])
def test_the_scalar_scale_defaults_to_the_ciphertexts(key, cpow):
    """`scalar_scale_pow10` unset means "the ciphertext's", not "eight".

    Checked away from the default on purpose: at `cpow=8` the correct
    expression and the wrong one produce the same byte, so a test there
    proves nothing. Here the product's scale must come out at `2·cpow`.
    """
    pub, _ = key
    blob = one(pub, 2.0, scale_pow10=cpow)

    product = bytes(p.multiply_many_public(pub, [blob], [3.0])[0])

    assert product[0] == 2 * cpow, (
        f"product carries scale byte {product[0]}, expected {2 * cpow} "
        f"for a ciphertext at 1e{cpow}"
    )


def test_a_ciphertext_outside_the_key_range_is_refused(key):
    """`cipher ≥ n²` has to be a refusal, not a reduction.

    Removing the range check left the upper bound to nothing at all: an
    oversized blob is silently taken modulo `n²` and multiplied, which
    returns a number rather than an error. The lower bound is now caught
    incidentally by the gcd check (`gcd(0, n) = n`); the upper one is
    not caught by anything else.
    """
    pub, _ = key
    n = int.from_bytes(pub.modulus_bytes(), "big")
    header = bytes(one(pub, 1.0))[:1]

    too_big = n * n + 7
    blob = header + too_big.to_bytes((too_big.bit_length() + 7) // 8, "big")

    with pytest.raises(ValueError, match=r"\[1, n\^2\)"):
        p.multiply_many_public(pub, [blob], [2.0])


def test_the_product_decrypts_to_the_product(key):
    pub, sec = key
    blob = one(pub, 2.5)
    out = bytes(p.multiply_many_public(pub, [blob], [4.0])[0])
    assert p.decrypt(sec, out) == pytest.approx(10.0, abs=1e-9)


def test_a_negative_scalar_inverts_the_base(key):
    """The path `pow_mod` takes for a negative exponent, exercised."""
    pub, sec = key
    out = bytes(p.multiply_many_public(pub, [one(pub, 6.0)], [-0.5])[0])
    assert p.decrypt(sec, out) == pytest.approx(-3.0, abs=1e-9)


# ---------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------

def test_a_scalar_encoding_to_zero_is_refused(key):
    """`E(x)^0 = 1` destroys the value and marks the result as
    recognisably zero to anyone holding the bytes."""
    pub, _ = key
    with pytest.raises(ValueError, match="encodes to zero"):
        p.multiply_many_public(pub, [one(pub, 1.0)], [1e-12])


def test_a_scalar_past_the_float_exactness_limit_is_refused(key):
    """Past `2^53` an `f64` no longer holds every integer, so the value
    used would not be the value asked for.

    This bound is STRICTER than `multiply_many`'s, not looser: 2^53 is
    below 2^64 at every scale. The other function accepts values this one
    refuses — a unix timestamp among them — and rounds them silently.
    That is the trade, and the test pins which side of it we are on.
    """
    pub, _ = key
    with pytest.raises(ValueError, match="2\\^53"):
        p.multiply_many_public(pub, [one(pub, 1.0)], [1e10])


def test_the_narrower_bound_is_a_refusal_where_the_other_path_rounds(key):
    """The direction of the difference, pinned.

    Measured across 3000 combinations: 108 inputs this path refuses and
    `multiply_many` accepts, none the other way round. If that ever
    reverses, one of the two bounds moved and the documentation is
    describing the wrong function.
    """
    pub, _ = key
    blob = one(pub, 1.0)

    # A unix timestamp at the default scale: 1.7e9 · 1e8 > 2^53.
    p.multiply_many(pub, [blob], [1.7e9])  # accepted there
    with pytest.raises(ValueError, match="2\\^53"):
        p.multiply_many_public(pub, [blob], [1.7e9])  # refused here

    # And the way through is a lower scalar scale, not a bigger key.
    out = p.multiply_many_public(
        pub, [blob], [1.7e9], scalar_scale_pow10=2,
    )
    assert len(bytes(out[0])) > 0


def test_a_length_mismatch_is_refused(key):
    pub, _ = key
    with pytest.raises(ValueError, match="paired by position"):
        p.multiply_many_public(pub, [one(pub, 1.0)], [1.0, 2.0])


def test_a_non_ciphertext_is_refused_whatever_the_sign(key):
    """The blocker this test exists for.

    `pow_mod` reports non-invertibility only for a NEGATIVE exponent,
    because only then does it need the inverse. Left to it, a value
    sharing a factor with `n` — `n` itself, for instance — sailed through
    on positive scalars and was refused on negative ones: the same input
    accepted or rejected by the sign of an unrelated number.
    """
    pub, _ = key
    n = int.from_bytes(pub.modulus_bytes(), "big")
    # `n` lies inside [1, n²), so the range check does not catch it.
    fake = p.encrypt_many(pub, [1.0])[0]
    header = bytes(fake)[:1]
    bogus = header + n.to_bytes((n.bit_length() + 7) // 8, "big")

    for scalar in (2.0, -2.0, 1.0, -1.0):
        with pytest.raises(ValueError):
            p.multiply_many_public(pub, [bogus], [scalar])


def test_a_scale_overflow_is_refused(key):
    pub, _ = key
    with pytest.raises(ValueError, match="past the 1e18"):
        p.multiply_many_public(
            pub, [one(pub, 1.0)], [2.0], scalar_scale_pow10=18,
        )


# ---------------------------------------------------------------------
# The trade, measured
# ---------------------------------------------------------------------

def test_the_timing_does_depend_on_the_scalar(key):
    """The negative twin of `scalar.py`'s width test.

    That test asserts the secret path's time does NOT follow the
    scalar's bit length. This one asserts the public path's time DOES —
    because that is precisely what was sold for the speed, and a fast
    path silently turned constant-width would be a 13× slowdown nobody
    ordered, while a secret path silently turned variable would be a leak
    nobody agreed to.
    """
    import time

    pub, _ = key
    blob = one(pub, 1.0)

    def fastest_time(scalar, rounds=40):
        samples = []
        for _ in range(rounds):
            start = time.perf_counter()
            p.multiply_many_public(pub, [blob], [scalar])
            samples.append(time.perf_counter() - start)
        # `min`, not the median: the median tracks how busy the machine
        # is, the minimum tracks the operation. Same reasoning as
        # `scalar.py:294`, where it is written down at length.
        return min(samples)

    small = fastest_time(1e-7)      # ~4 bits once encoded
    large = fastest_time(1000.0)    # ~37 bits once encoded

    assert large > small * 3, (
        f"a 33-bit wider exponent cost {large / small:.2f}x, not the "
        f"several-fold this path trades away. Either the fast path is "
        f"gone or the measurement is being drowned"
    )


# ---------------------------------------------------------------------
# Reference vectors
# ---------------------------------------------------------------------
#
# A written-down modulus, a written-down ciphertext, and the written-down
# bytes their product must produce. Not for the arithmetic — the tests
# above cover that — but for the case where two builds disagree. That
# failure does not raise: it returns a number that looks entirely
# reasonable, and only a pinned expected value sees it.
#
# What can be pinned and what cannot: encryption draws randomness, so a
# ciphertext is not reproducible and is fixed here as INPUT. The product
# of a fixed ciphertext by a fixed scalar is deterministic, and that is
# the half `pow_mod` decides — the half a rebuild could change. The
# decrypting side is not pinned because a private key cannot be assembled
# from `p` and `q` through this API at all.

_REF_N_HEX = (
    "b922274a70ad887a2f475bafefa70137677ef757ee460bd7716de224811d9a1c"
    "978b08cfc8341671fe683975a7848b3b6e8d14ab087008e3adffc3e9c63598f0"
    "275bff74abbe3bf00511706d7433e00328e05f4a3094482ef113af585f379ae6"
    "0ecd5fee6099ed7bb2f96e74adf01aa4d9a749bd28c76a775a6d5d218314c54e"
    "45d2ab6d53e6aa227aacae3592030796afba749f5f3669ef13c34aeffbee48f1"
    "f1a696685cf8ccebb7de7c0440f83c5e9ac775095bf96b7b879178f9662cb106"
    "61f449f90748aeb9132922566d45aedeba5e620b805a1275041b28bc887388fc"
    "0c3764b9015f09fc430474ef86b52d37da6aa18749bb090f3855c715e2f701b5"
)

_REF_CT_HEX = (
    "083c5f09246d26d8271b6236e74bb2d1804ee71248b14a98b8597ce83614dddc"
    "ce9ea6fe843f693e4f41b5e6337a22f5cfdc5e6e8a11caa883f832f8ecf454fd"
    "2e2488769f018017082626f32841d5fece5d8bbc85426f9e271ef14b65dc9b5a"
    "8cb5c1f4103cc978ee8ba8fdeb5fe9c13451e37d27f2698e9977698fe594c70f"
    "1c2a4915c44248e2fcbac2ef3870b0834af5bb5b4e4a675bd8e8f60d669d5896"
    "5bcfc083bb650cd9a830e16d11264c1a4f4481d41a7959403d27fd149c73e825"
    "106caa8ece7e6a3992722fecc46175790c7777ef0112ab3cef37c3957065aaae"
    "734f57ba0c2fe59fb99f00634a46436de0bea044453a282462f31fd9a119d239"
    "62bb8c9838c3a3016227f0cc6b2f2491bbb18a1e41cb0ae78a5ef1f47c420333"
    "be78595a998e115b553b7f04c5b20210b113e6109c0b0f3bca8a731def8cc1ee"
    "7eac96bbf922a48f3021cf3dabfd065e6248c290eb088da5838a5e8aed22193f"
    "9ea0ba5d42d73c4a7df9767fb24ca8cbb8c5fa9523da84ece9c8ebe571b96c5d"
    "424bb9113dff5eb831b285783e404b0e698d185ba9005412ef2bbe9836a45b71"
    "ae79a1928ecbdee0fc4f31c9baad73fdabb19749ca521b5dfe36b23b67e33477"
    "150306022b0a41cb8ca94efd8b7f0578cb3abd49e05a41f8f84564c7d8a0ee7d"
    "607d4485abe1c7807dc30960bd6ea948cdab0753ea709269368b3794bdd24a52"
    "6a"
)
_REF_PRODUCT_HEX = (
    "103691c26e104afab74ed44e212af2c90020a1e62833e005a66d20996de369ff"
    "40b7101f4b7890a649b779e5772274b70e299e4f191eea6b4938e660faf60779"
    "fb31ff4e1371fbc134cb9862ae5868568d988d3da12b7a3b5242c11be228c02c"
    "f84f51817e6cac4300c82839badd5c5558d2c2509a359893a59d778920a9ef71"
    "653926bcbfc954cc5f1170241735d8222051fa8b483b5c5ab7d9dc4f722067ff"
    "d8100ffe1db15148549ac16a3da7cf2a3da3c1891e0427970bb23a7caa7561be"
    "6659a4ec19b09c2e7a561faecfe1647a30bcde042bb93b355b52a5e4c7e6f629"
    "8e737e672fbfba0a04e7df72c712b3743cff86c2d534421f55bf5b312923a242"
    "ac8643b4fee84125047aeca411c065ed308508794307ed985a66f4a5fbe88290"
    "23466ff32619646e099b4bb837d19c5f86e79f29572ba34228419241f02b335b"
    "96b922ee8a5c033dedae3b0e92231cae6b1b9595914f3a5308e62c06d81725fe"
    "6e310a021ea23e5eeb46bdf0710ab18cbd8d67b3f12ab66ed12a840e38217c55"
    "cd68e12e8b56cbb186666bf3aabacc66ac06f59fcbf9089d9e89dff01cd8a348"
    "9d13d03a56e887538a774a1419cc4482ade2202d7b4ae5747d7211bc3dfde6b2"
    "56e3db384a5cbc6fca40a91e09b005c82ca1347d312e5e928d6f613772882fc8"
    "8e5f34200605c24a713f0e3fc2f867b6ad07d6f583f06124d4712a4c4868cdf7"
    "c8"
)


def _ref_key():
    return p.PublicKey.from_n(bytes.fromhex(_REF_N_HEX))


def test_the_reference_product_is_byte_for_byte_what_it_was():
    """The pinned vector. If this fails, the two sides of a federation
    are about to compute different numbers and call them the same."""
    pub = _ref_key()
    ct = bytes.fromhex(_REF_CT_HEX)

    product = bytes(p.multiply_many_public(pub, [ct], [8.0])[0])

    assert product.hex() == _REF_PRODUCT_HEX, (
        "the product of a fixed ciphertext by a fixed scalar under a "
        "fixed key changed. Either the exponentiation or the blob "
        "encoding moved; both are silent in every other test"
    )


def test_the_reference_vector_agrees_across_both_paths():
    """The same pinned bytes through the secret path.

    The two functions are meant to be interchangeable in result. Pinning
    only one of them would let them drift apart while each stayed
    self-consistent.
    """
    pub = _ref_key()
    ct = bytes.fromhex(_REF_CT_HEX)

    assert bytes(p.multiply_many(pub, [ct], [8.0])[0]).hex() == (
        _REF_PRODUCT_HEX
    )
