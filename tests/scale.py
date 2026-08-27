"""The encoding scale: configurable, with nothing left to disagree about.

The scale is a property of the CIPHERTEXT, not a setting on the call. The
reason is that a scale mismatch produces not a refusal but a plausible
wrong number: same bytes, same length, same shape — only the result is
`10^Δ` times smaller. The checks here guard exactly that.

Separately about the passive side: it builds a peer key from `n` alone
(`PublicKey.from_n`), and `n` carries no scale. So with a setting "on the
side" the peer would take the default and silently disagree with the key
holder. Hence the scale travels in the blob, and
`test_a_peer_reads_the_scale_from_the_blob` is about that, not about
serialisation.
"""
import pytest

import paillier as p

BITS = 2048


@pytest.fixture(scope="module")
def key():
    return p.generate_keypair(BITS)


def one(pub, value, **kw):
    return bytes(list(p.encrypt_many(pub, [value], **kw))[0])


@pytest.mark.parametrize("pow10", [0, 3, 8, 12, 15, 18])
def test_the_round_trip_at_every_scale(key, pow10):
    """The encoding error is `1/(2·10^e)`, and that is what to judge by.

    A fixed tolerance will not do: at `e = 0` only integers are encoded
    and `1.5` comes back as `2.0`. The tolerance has to follow the scale,
    or the test is falsely red at the bottom and blind at the top.
    """
    pub, sec = key
    value = 1.5

    back = p.decrypt(sec, one(pub, value, scale_pow10=pow10))

    assert abs(back - value) <= 1.0 / (2 * 10 ** pow10)


def test_decryption_takes_the_scale_from_the_blob(key):
    """The principal check of this file.

    If `decrypt` took the scale from the default, a value encrypted at
    `1e12` would come back TEN THOUSAND TIMES SMALLER — finite,
    plausible, without a single sign of anything wrong.
    """
    pub, sec = key
    value = 1234.5678

    back = p.decrypt(sec, one(pub, value, scale_pow10=12))

    assert back == pytest.approx(value, abs=1e-9)


def test_a_peer_reads_the_scale_from_the_blob(key):
    """A peer builds the key from `n` alone and does not know the scale.

    This is not about serialisation but about the two sides never needing
    to agree on a scale at all.
    """
    pub, sec = key
    peer = p.PublicKey.from_n(pub.modulus_bytes())

    back = p.decrypt(sec, one(peer, -7.25, scale_pow10=15))

    assert back == pytest.approx(-7.25, abs=1e-12)


def test_a_sum_of_mixed_scales_is_refused(key):
    """A refusal, not a conversion to a common scale.

    Converting would mean multiplying the plaintext, and the plaintext is
    encrypted. So the choice is to refuse or to return nonsense.
    """
    pub, _ = key
    blobs = [one(pub, 1.0, scale_pow10=8), one(pub, 2.0, scale_pow10=12)]

    with pytest.raises(ValueError, match="scale"):
        p.add_many(pub, blobs)


def test_a_sum_keeps_its_scale(key):
    """Otherwise the refusal above would be useless: the sum of a batch at
    `1e12` has to add to the next such batch."""
    pub, sec = key
    blobs = [one(pub, v, scale_pow10=12) for v in (1.5, 2.25, -0.75)]

    total = p.add_many(pub, blobs)

    assert p.decrypt(sec, total) == pytest.approx(3.0, abs=1e-9)
    # And the result adds again — the scale survived in the blob.
    assert p.decrypt(sec, p.add_many(pub, [bytes(total), blobs[0]])) == (
        pytest.approx(4.5, abs=1e-9)
    )


@pytest.mark.parametrize("pow10", [19, 200, 255])
def test_too_large_a_scale_is_refused(key, pow10):
    pub, _ = key

    with pytest.raises(ValueError, match="scale exponent"):
        p.encrypt_many(pub, [1.0], scale_pow10=pow10)


def test_a_blob_with_a_foreign_exponent_is_refused_on_decryption(key):
    """The exponent arrives over the wire, so it is input, not a constant."""
    pub, sec = key
    blob = bytearray(one(pub, 1.0))
    blob[0] = 200

    with pytest.raises(ValueError, match="scale exponent"):
        p.decrypt(sec, bytes(blob))


def test_an_empty_blob_is_refused(key):
    _, sec = key

    with pytest.raises(ValueError):
        p.decrypt(sec, b"")


def test_the_scale_really_does_improve_the_sum(key):
    """What the setting exists for — with a number, not in words.

    The input is NON-NEGATIVE: on symmetric input the biases of opposite
    signs cancel and the gain from the scale is far harder to see.

    The lower check is not optional: without it the test would be green on
    a pair of zeros too, since "one is fifty times smaller than the other"
    holds for two very small quantities where the ratio is just noise. We
    require the error at `1e8` to be visible in the first place.
    """
    from fractions import Fraction
    import random

    pub, sec = key
    random.seed(20260826)
    values = [random.uniform(0.0, 1000.0) for _ in range(10_000)]
    exact = sum((Fraction(v) for v in values), Fraction(0))

    def error(pow10):
        blobs = [bytes(b) for b in p.encrypt_many(pub, values, scale_pow10=pow10)]
        got = p.decrypt(sec, p.add_many(pub, blobs))
        return float(abs(Fraction(got) - exact))

    coarse = error(8)
    fine = error(12)

    assert coarse > 1e-8, f"at 1e8 the error is {coarse:.2e} — nothing to measure"
    assert fine * 50 < coarse, f"1e12 gave {fine:.2e} against {coarse:.2e} at 1e8"
