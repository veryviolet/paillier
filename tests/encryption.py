"""Encryption with a short exponent.

There used to be no checks on it at all, and the suite stayed green on
code with no privacy: the mutation "an 8-bit exponent" passed, and so did
"`hs = 1`".

Run against the built module:
    PYTHONPATH=<where paillier.so lives> python -m pytest tests/encryption.py
"""

import math
import time

import pytest

import paillier as p

# The modulus length floor. Anything shorter and `generate_keypair`
# refuses, rightly.
BITS = 2048

# 2050 deserves its own case: the product of two 1025-bit primes comes out
# at 2049 bits, and everything computing the exponent length from the
# REQUESTED size disagrees here with everything computing it from the
# actual one.
ODD_BITS = 2050


@pytest.fixture(scope="module")
def key():
    return p.generate_keypair(BITS)


def exponent_bits_of(pub):
    """The expected exponent length — half of the ACTUAL modulus."""
    modulus_bits = int.from_bytes(pub.modulus_bytes(), "big").bit_length()
    return ((modulus_bits // 2 + 7) // 8) * 8


def one(pub, value):
    return list(p.encrypt_many(pub, [value]))[0]


def cipher_int(blob):
    """The ciphertext as a number, WITHOUT the scale header.

    The first byte of the blob is the power-of-ten exponent. Parsing the
    whole blob as one integer gives a number about 2^4096 times larger
    than the actual ciphertext, and any quantity computed modulo `n²`
    turns into noise. Three tests below KEPT PASSING after the header was
    introduced, while checking garbage: their assertions are of the form
    "not equal" and "not one", and garbage satisfies those.
    """
    return int.from_bytes(bytes(blob)[1:], "big")


# ---------------------------------------------------------------------
# Round trip and homomorphism
# ---------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    0.0, 1.0, -1.0, 0.5, -0.5, 1e-8, -1e-8, 12345.678, -98765.4321,
])
def test_round_trip(key, value):
    pub, sec = key

    assert p.decrypt(sec, one(pub, value)) == pytest.approx(value, abs=1e-7)


def test_homomorphism_including_a_crossing_of_zero(key):
    pub, sec = key
    blobs = list(p.encrypt_many(pub, [10.0, -3.5, -20.0, 1.25]))

    total = p.decrypt(sec, p.add_many(pub, blobs))

    assert total == pytest.approx(10.0 - 3.5 - 20.0 + 1.25, abs=1e-6)


# ---------------------------------------------------------------------
# Randomisation — what gets lost silently
# ---------------------------------------------------------------------

def test_one_value_gives_different_ciphertexts(key):
    """Catches an `hs` of degenerate order and a lost call to the RNG."""
    pub, _ = key

    blobs = p.encrypt_many(pub, [7.0] * 200)

    assert len({bytes(b) for b in blobs}) == 200


def test_the_exponent_length_is_pinned_BY_NUMBER(key):
    """Half the modulus length, and that is checked directly.

    Judging by collisions among encryptions will not do: it was measured
    that with an exponent of 64, 128 or 192 bits there are no collisions
    at all among six hundred encryptions, while the strength at 64 bits is
    already `2^32` — minutes of work. Such a check catches only a collapse
    to the birthday bound, i.e. down to about eight bits.

    This is what a units typo looks like — `bits/2` bytes instead of bits
    — or an edit of `/2` into `/4`.
    """
    pub, _ = key

    assert pub.exponent_bits == exponent_bits_of(pub)


def test_a_peer_key_takes_the_same_exponent_length(key):
    """Two formulas in two places drift apart silently: `generate_keypair`
    computed from the requested bits, `from_n` from the actual ones."""
    pub, _ = key

    peer = p.PublicKey.from_n(pub.modulus_bytes())

    assert peer.exponent_bits == pub.exponent_bits


def test_the_exponent_length_agrees_when_the_modulus_is_short_of_the_request():
    """The test above was green at 1024 bits by coincidence.

    At a request of 1026 the modulus came out at 1025 bits: the owner took
    520 bytes from the REQUESTED size and the peer 512 from the actual
    one, so ciphertexts from the two sides under one key got exponents of
    different lengths.

    The discrepancy does not always arise: the product of two primes of
    `bits/2` bits comes out at both `bits` and `bits−1`, depending on how
    the top bits fall. So the key is SEARCHED FOR rather than taken as it
    comes: a test relying on luck here goes red every other run, and I
    have already had that.
    """
    attempts = 0
    while True:
        attempts += 1
        assert attempts <= 20, "no modulus short of the request in 20 attempts"
        pub, _ = p.generate_keypair(ODD_BITS)
        modulus_bits = int.from_bytes(pub.modulus_bytes(), "big").bit_length()
        if modulus_bits < ODD_BITS:
            break

    peer = p.PublicKey.from_n(pub.modulus_bytes())

    assert exponent_bits_of(pub) != ((ODD_BITS // 2 + 7) // 8) * 8, (
        "the size is chosen so that the formulas from the actual and from "
        "the requested value give DIFFERENT answers — otherwise the mutation "
        "is not caught"
    )
    assert pub.exponent_bits == exponent_bits_of(pub)
    assert peer.exponent_bits == pub.exponent_bits


def test_encryptions_of_one_value_do_not_repeat(key):
    """Separate from the length: catches a collapse of the randomiser down
    to a handful of values."""
    pub, _ = key

    blobs = p.encrypt_many(pub, [1.0] * 600)

    assert len({bytes(b) for b in blobs}) == 600


def test_the_randomiser_does_not_repeat_across_calls(key):
    """The check above is blind to `r` being reused across DIFFERENT
    plaintexts — and that is exactly what a process fork with a shared
    seed looks like.

    The quantity is computed from the public key alone: if `r` coincided
    then `c₁·c₂⁻¹ ≡ 1 + (m₁−m₂)·n`, i.e. it is one modulo `n`.
    """
    pub, _ = key
    n = int.from_bytes(pub.modulus_bytes(), "big")
    nn = n * n

    left = cipher_int(one(pub, 11.0))
    right = cipher_int(one(pub, 22.0))

    ratio = left * pow(right, -1, nn) % nn
    assert ratio % n != 1, "the randomiser coincided across two encryptions"


@pytest.fixture(scope="module")
def peer(key):
    """A peer key: built from the modulus ALONE, with `hs` derived in
    place."""
    pub, _ = key
    return p.PublicKey.from_n(pub.modulus_bytes())


def test_a_peer_key_randomises_encryption(peer):
    """Every randomisation check used to stand on the owner's key, and the
    peer path was checked only for the round trip and addition.

    The mutation "`hs = 1` in `from_n`" passed the whole suite: `c` is
    exactly `1 + m·n`, i.e. there is no privacy for precisely the side
    that deriving `hs` in place exists for.
    """
    blobs = p.encrypt_many(peer, [7.0] * 200)

    assert len({bytes(b) for b in blobs}) == 200


def test_the_peers_randomiser_does_not_repeat_across_calls(peer):
    """The same as for the owner: the quantity is computed from one public
    key, without knowing `r`."""
    n = int.from_bytes(peer.modulus_bytes(), "big")
    nn = n * n

    left = cipher_int(one(peer, 11.0))
    right = cipher_int(one(peer, 22.0))

    ratio = left * pow(right, -1, nn) % nn
    assert ratio % n != 1, "the randomiser coincided across two encryptions"


def test_a_peer_ciphertext_is_not_the_encoding_of_the_plaintext(peer):
    """A direct sign of `hs = 1`: then `c` is exactly `1 + m·n`.

    The check above catches this through ciphertexts differing, but
    catches it indirectly; here the value itself is produced.
    """
    n = int.from_bytes(peer.modulus_bytes(), "big")

    blob = cipher_int(one(peer, 3.5))

    assert blob != 1 + round(3.5 * 10**8) * n


# ---------------------------------------------------------------------
# Refusals instead of a plausible number
# ---------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    float("nan"), float("inf"), float("-inf"),
])
def test_non_finite_values_are_refused(key, value):
    """These used to turn into a confident zero and travel into the sum."""
    pub, _ = key

    with pytest.raises(ValueError):
        p.encrypt_many(pub, [value])


@pytest.mark.parametrize("value", [1.7976931348623157e308, -1.7976931348623157e308])
def test_overflow_during_scaling_is_refused(key, value):
    """`v · SCALE` goes to infinity, and no encoding exists.

    Such a value used to come back as `−4.8e299` — a finite number of the
    wrong sign.
    """
    pub, _ = key

    with pytest.raises(ValueError):
        p.encrypt_many(pub, [value])


def test_the_sum_headroom_covers_the_whole_f64_range(key):
    """The range check CANNOT fire on a 2048-bit key, and that has to be
    asserted with a number rather than by hunting for a value it refuses.

    The old test fed `1e300` and demanded a refusal. It was green only
    because it stood on a 1024-bit key, where `n/2 ≈ 1e308`. With a floor
    of 2048 bits, `1e300` is a perfectly lawful value and must not be
    refused.

    What is asserted is what actually keeps privacy safe from a silent
    overflow: the sum headroom covers, by a wide margin, everything that
    can be encoded from an `f64` at all.
    """
    pub, sec = key
    modulus_bits = int.from_bytes(pub.modulus_bytes(), "big").bit_length()
    largest_encodable = 1.79e300

    # EQUALITY, not "greater than". It used to be
    # `1024 < plaintext_bound_bits` with a thousand bits of slack — an
    # inequality satisfied by a completely wrong value too, and a mutation
    # of the getter into `n.significant_bits()` (an error of 21 bits)
    # passed the whole suite.
    assert pub.plaintext_bound_bits == modulus_bits - 21

    assert int(largest_encodable * 10**8).bit_length() < pub.plaintext_bound_bits

    blob = one(pub, largest_encodable)
    assert p.decrypt(sec, blob) == pytest.approx(largest_encodable, rel=1e-12)


def test_a_peer_modulus_cannot_be_arbitrarily_long():
    """Denial of service, not cryptographic strength.

    Assembling a peer key runs with the GIL released, so `SIGINT` does not
    reach the process until it returns. The modulus arrives from the peer
    over the wire.
    """
    huge = (2 ** 16384 + 1).to_bytes(2049, "big")

    with pytest.raises(ValueError):
        p.PublicKey.from_n(huge)


def test_the_length_refusal_does_not_depend_on_the_input_length():
    """The length bound must stand BEFORE any arithmetic.

    One `pytest.raises` is not enough: the refusal happened before too,
    but `n²` was computed BEFORE the length check, so the cost of the
    refusal grew with input the attacker fully controls. Measured on the
    old code: 0.009 s at 256 KB, 0.404 at 8 MB, 1.92 at 32 MB, **4.07 at
    64 MB** — all of it with the GIL held, i.e. the interpreter executes
    nothing at all, signal handlers included. Plus a twofold amplification
    in memory.

    The quantity is the RATIO of times, not the absolute time: the
    absolute depends on the machine, the ratio does not. On the old code
    it was about 450; now the refusal does not look at the contents at
    all. A threshold of 10 leaves fortyfold headroom and does not trip on
    scheduler jitter.
    """
    small = b"\xff" * (256 * 1024)
    large = b"\xff" * (64 * 1024 * 1024)

    def refusal_seconds(raw):
        best = None
        for _ in range(3):
            started = time.perf_counter()
            with pytest.raises(ValueError):
                p.PublicKey.from_n(raw)
            taken = time.perf_counter() - started
            best = taken if best is None else min(best, taken)
        return best

    on_small = refusal_seconds(small)
    on_large = refusal_seconds(large)

    assert on_large / max(on_small, 1e-9) < 10, (
        f"the refusal at 64 MB took {on_large:.4f} s against {on_small:.4f} s "
        f"at 256 KB — so the length is checked after work on the contents"
    )


def test_an_empty_sum_is_refused(key):
    pub, _ = key

    with pytest.raises(ValueError):
        p.add_many(pub, [])


def test_an_over_long_key_is_refused():
    """The value next to the bound — catches an off-by-one."""
    with pytest.raises(ValueError):
        p.generate_keypair(8193)


def test_a_very_long_key_is_refused_QUICKLY():
    """The upper bound was introduced only for a PEER's modulus.

    Our own stayed unbounded: `generate_keypair(200000)` was still alive
    eleven seconds later and `SIGINT` did not take it — the same
    uninterruptible class as at the lower end, closed on one side only.

    In a separate process, like the lower bound: an in-place check does
    not work here, because when the check fails the call does not return —
    a mutation run already demonstrated that by hanging for half an hour.
    """
    import subprocess
    import sys

    done = subprocess.run(
        [sys.executable, "-c", "import paillier; paillier.generate_keypair(200000)"],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert done.returncode != 0, "a 200000-bit key must be refused"
    assert "8192" in done.stderr, done.stderr[-400:]


@pytest.mark.parametrize("bits", [32, 256, 1024, 2047])
def test_a_short_key_is_refused(bits):
    """There was no bound at all.

    `generate_keypair(32)` returned a 32-bit modulus and the suite stayed
    entirely green: the round trip is right, the homomorphism is right,
    the key checks are content, and `n` factors in microseconds. What has
    to be checked is the refusal, because everything else here is in
    order.

    2047 stands separately: the value next to the bound catches an
    off-by-one.
    """
    with pytest.raises(ValueError):
        p.generate_keypair(bits)


def test_a_short_key_is_refused_QUICKLY():
    """The refusal must come BEFORE the prime search.

    `generate_safe_prime` at eight bits spins forever, and it runs with
    the GIL released, so Python's signal handler never executes:
    `generate_keypair(16)` ended neither on Ctrl-C nor on an external
    `SIGINT`. An in-place check will not catch this — the process simply
    does not return — hence a separate run, with a timeout.

    The test is also green on code where the length check stands AFTER the
    prime search: at 32 bits primes are found instantly. What makes it red
    is 16.
    """
    import subprocess
    import sys

    done = subprocess.run(
        [sys.executable, "-c", "import paillier; paillier.generate_keypair(16)"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert done.returncode != 0, "a 16-bit key must be refused"
    assert "2048" in done.stderr, done.stderr[-400:]


def test_a_bad_ciphertext_raises_rather_than_panics(key):
    """`PanicException` inherits from `BaseException`, not `Exception`, so
    a panic passes straight through the caller's `except Exception` and
    kills the process.

    An empty sum got a tidy refusal, while a neighbouring input of the
    same origin panicked at `.expect("oadd")`.
    """
    pub, _ = key
    good = one(pub, 1.0)

    with pytest.raises(ValueError):
        p.add_many(pub, [bytes(good), b"\x00"])


def test_a_sum_beyond_the_headroom_is_refused(key):
    """Per-value range checking is not enough: it is the SUM that
    overflows.

    On a 1024-bit key three lawful values of `2.29e299` added up to
    `−4.57e299` — a finite, plausible number of the wrong sign. The
    headroom is reserved at encryption time, but it holds exactly up to
    the declared number of terms, and that number has to be a bound rather
    than a wish.
    """
    pub, _ = key
    terms = 2**20 + 1

    with pytest.raises(ValueError):
        p.add_many(pub, [b"\x01"] * terms)


def test_a_sum_within_the_headroom_adds_correctly(key):
    """The other side: the bound must not get in the way of normal work."""
    pub, sec = key

    blobs = list(p.encrypt_many(pub, [1e30, 1e30, -2e30]))

    assert p.decrypt(sec, p.add_many(pub, blobs)) == pytest.approx(0.0, abs=1e22)


# ---------------------------------------------------------------------
# The peer key: what deriving `hs` in place exists for
# ---------------------------------------------------------------------

def test_a_key_is_built_from_the_modulus_alone(key):
    """The encrypting side receives only `n` and derives `hs` itself."""
    pub, sec = key

    peer = p.PublicKey.from_n(pub.modulus_bytes())
    blob = one(peer, 42.5)

    assert p.decrypt(sec, blob) == pytest.approx(42.5, abs=1e-7)


def test_different_hs_under_one_modulus_still_add(key):
    """Without this, deriving in place has no right to exist: ciphertexts
    from two sides that derived DIFFERENT `hs` must add and decrypt
    correctly."""
    pub, sec = key
    modulus = pub.modulus_bytes()

    first = p.PublicKey.from_n(modulus)
    second = p.PublicKey.from_n(modulus)

    blobs = [one(first, -4321.0), one(second, 9876.0)]
    total = p.decrypt(sec, p.add_many(first, blobs))

    assert total == pytest.approx(5555.0, abs=1e-6)


def test_an_even_modulus_is_refused():
    """The input must be of a LAWFUL LENGTH, or the test proves something
    else.

    It used to feed `2**64` — 65 bits. Such a modulus is refused on
    length, and the test stayed green on code with no oddness check at
    all: it asserted only "some ValueError". The discriminating input is
    an even modulus that passes the length check.
    """
    even = (2 ** 2048).to_bytes(257, "big")

    with pytest.raises(ValueError, match="odd"):
        p.PublicKey.from_n(even)


def test_a_short_peer_modulus_is_refused():
    """`from_n` did not check a PEER's modulus in any way.

    What is checked is what everyone checks: oddness and length —
    *partial public key validation*. What is judged here is that the check
    is CALLED from `from_n` at all; what exactly it refuses is in
    `tests/smooth_order_attack.rs`.
    """
    short = (2 ** 2000 + 1).to_bytes(251, "big")

    with pytest.raises(ValueError):
        p.PublicKey.from_n(short)


def test_the_key_path_end_to_end(key):
    """Serialisation → transfer → encryption → decryption.

    Catches a modulus lost along the way, which per-layer checks do not
    see.
    """
    pub, sec = key

    wire = bytes(pub.modulus_bytes())
    assert len(wire) == math.ceil(BITS / 8)

    peer = p.PublicKey.from_n(wire)
    blobs = list(p.encrypt_many(peer, [1.0, 2.0, 3.0]))

    assert p.decrypt(sec, p.add_many(peer, blobs)) == pytest.approx(6.0, abs=1e-6)
