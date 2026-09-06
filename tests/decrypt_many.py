"""Batched decryption that stays in the integers.

`decrypt` returns `f64`. That is fine for a magnitude and wrong for an
aggregate: a homomorphic sum of encoded gradients passes `2**53` on an
ordinary node, and past that an odd integer does not survive a `f64` at
all. The value that comes back is not flagged, not out of range and not
implausible — it is simply a different number, and downstream it picks a
different split.

So `decrypt_many` returns the plaintext as a DECIMAL STRING and refuses a
scaled blob: a scale would divide the integer back into a float and put
the rounding it exists to avoid straight back in.

The first test below is the one that justifies the function. It is
written so that it FAILS if `decrypt_many` is ever reimplemented on top
of `decrypt`, which is the obvious simplification and destroys the
property.
"""
import pytest

import paillier as p

BITS = 2048

# 2**52 + 2**52 + 1. Each term is an integer an f64 holds exactly, and
# their sum is an odd integer above 2**53 — which an f64 does not hold:
# above 2**53 the representable integers are the even ones.
TERMS = [4503599627370496.0, 4503599627370496.0, 1.0]
EXACT = "9007199254740993"


@pytest.fixture(scope="module")
def key():
    return p.generate_keypair(BITS)


def encrypt(pub, values, **kw):
    kw.setdefault("scale_pow10", 0)
    return [bytes(b) for b in p.encrypt_many(pub, values, **kw)]


def test_a_sum_above_two_to_the_53_comes_back_exactly(key):
    pub, sec = key
    total = bytes(p.add_many(pub, encrypt(pub, TERMS)))

    assert p.decrypt_many(sec, [total]) == [EXACT]


def test_and_the_float_path_does_not(key):
    """The control for the test above. Without it, that test passes on a
    `decrypt_many` that simply formats `decrypt`'s `f64` — the two agree
    on every value small enough to be representable, and the fixture
    above would be the only thing standing between them.

    This asserts the LOSS, so it fails if the premise is wrong: if
    `decrypt` were exact here, the function under test would have no
    reason to exist.
    """
    pub, sec = key
    total = bytes(p.add_many(pub, encrypt(pub, TERMS)))

    assert str(int(p.decrypt(sec, total))) != EXACT


def test_ordinary_values_agree_with_decrypt(key):
    """Exactness is not licence to disagree with `decrypt` anywhere it is
    right.
    """
    pub, sec = key
    values = [0.0, 1.0, -1.0, 42.0, -1000000.0]
    blobs = encrypt(pub, values)

    assert p.decrypt_many(sec, blobs) == [str(int(v)) for v in values]
    assert [int(p.decrypt(sec, b)) for b in blobs] == [int(v) for v in values]


def test_the_results_come_back_in_the_order_the_blobs_were_given(key):
    """Decryption runs across cores; the answers must not arrive in
    completion order. Distinct values, so a misplaced result shows.
    """
    pub, sec = key
    values = [7.0, -3.0, 11.0, 0.0, 5.0, -9.0]

    assert p.decrypt_many(sec, encrypt(pub, values)) == [
        str(int(v)) for v in values
    ]


def test_nothing_to_decrypt_is_not_an_error(key):
    pub, sec = key
    assert list(p.decrypt_many(sec, [])) == []
    assert pub is not None


def test_a_scaled_blob_is_refused_by_its_scale(key):
    """A scale means the caller wanted a magnitude, and a magnitude comes
    back through `decrypt`. Dividing here would reintroduce exactly the
    rounding this function exists to avoid, and it would do it silently.
    """
    pub, sec = key
    blobs = encrypt(pub, [1.5], scale_pow10=8)

    with pytest.raises(ValueError) as refusal:
        p.decrypt_many(sec, blobs)

    assert "1e8" in str(refusal.value)


def test_the_refusal_names_which_blob_was_scaled(key):
    """A batch is thousands of ciphertexts. "One of them is scaled" is
    not a diagnosis.
    """
    pub, sec = key
    blobs = encrypt(pub, [1.0, 2.0]) + encrypt(pub, [3.0], scale_pow10=8)

    with pytest.raises(ValueError) as refusal:
        p.decrypt_many(sec, blobs)

    assert "#3" in str(refusal.value)


def test_a_value_that_is_not_a_ciphertext_is_refused(key):
    pub, sec = key
    blobs = encrypt(pub, [1.0, 2.0])
    spoiled = blobs[1][:1] + bytes(len(blobs[1]) - 1)

    with pytest.raises(ValueError) as refusal:
        p.decrypt_many(sec, [blobs[0], spoiled])

    assert "#2" in str(refusal.value)
