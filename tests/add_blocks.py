"""Summing many blocks over one array of ciphertexts.

`add_blocks` exists because the caller's shape is not one sum but
thousands of them over the same array, and driving that loop from Python
holds the GIL: on the caller's node it measured 98.4% of the work of one
tree node, beside encryption and re-randomisation that are already
parallel here.

Speed is not what these tests check. They check that the answer is the
same one a loop over `add_many` gives, that a block's result belongs to
THAT block, and that every refusal `add_many` makes is still made — a
faster function that quietly disagrees with the slow one about an empty
sum, a mixed scale or an out-of-range term would be worse than the loop
it replaces.

Two of the checks below are deliberately not "does it equal the loop":
an implementation that shares one accumulator across blocks, or that
returns the blocks in completion order rather than in the order given,
agrees with the loop on a single block and on a symmetric fixture, and
disagrees on nothing a recomputation test would notice.
"""
import pytest

import paillier as p

BITS = 2048

# `add_many` refuses more than this per sum, and `add_blocks` must refuse
# it per block. Mirrored from `SUM_HEADROOM_TERMS` in `src/lib.rs`, which
# is not exported to Python.
HEADROOM_TERMS = 1 << 20


@pytest.fixture(scope="module")
def key():
    return p.generate_keypair(BITS)


def encrypt(pub, values, **kw):
    kw.setdefault("scale_pow10", 0)
    return [bytes(b) for b in p.encrypt_many(pub, values, **kw)]


def by_loop(pub, blobs, blocks):
    return [
        bytes(p.add_many(pub, [blobs[i] for i in block])) for block in blocks
    ]


def test_agrees_with_a_loop_over_add_many(key):
    """The whole point: same arithmetic, different scheduling.

    Byte equality rather than plaintext equality, because both functions
    are deterministic — a result that decrypts correctly but differs in
    bytes would mean one of them is doing something else to the group
    element.
    """
    pub, _ = key
    blobs = encrypt(pub, [float(v) for v in range(1, 31)])
    blocks = [[0], [0, 1, 2], list(range(30)), [29, 0, 15]]

    assert [bytes(b) for b in p.add_blocks(pub, blobs, blocks)] == by_loop(
        pub, blobs, blocks
    )


def test_each_sum_is_the_sum_of_its_own_plaintexts(key):
    """An oracle that is not a recomputation by the same code path.

    The expected value is formed in Python from the integers that went
    in, so this fails if `add_blocks` and `add_many` are wrong together.
    """
    pub, sec = key
    values = [3.0, -8.0, 100.0, 0.0, 7.0]
    blobs = encrypt(pub, values)
    blocks = [[0, 1], [2, 3, 4], [4]]

    got = p.decrypt_many(sec, list(p.add_blocks(pub, blobs, blocks)))

    assert got == [
        str(sum(int(values[i]) for i in block)) for block in blocks
    ]


def test_the_results_come_back_in_the_order_the_blocks_were_given(key):
    """Parallel work completes out of order; the answers must not.

    Singleton blocks of DISTINCT values, so a result landing in the wrong
    slot is visible. With equal values, or with one block, an
    implementation that collects in completion order passes.
    """
    pub, sec = key
    values = [11.0, 22.0, 33.0, 44.0, 55.0, 66.0]
    blobs = encrypt(pub, values)
    blocks = [[4], [0], [5], [2], [1], [3]]

    got = p.decrypt_many(sec, list(p.add_blocks(pub, blobs, blocks)))

    assert got == [str(int(values[block[0]])) for block in blocks]


def test_a_term_used_by_several_blocks_is_not_consumed_by_the_first(key):
    """Every ciphertext is parsed once and shared between the blocks that
    name it. A shared accumulator, or a parsed value mutated in place,
    gives the first block the right answer and the rest a running total.
    """
    pub, sec = key
    blobs = encrypt(pub, [5.0, 9.0])
    blocks = [[0], [0], [0, 1], [0], [0, 0]]

    got = p.decrypt_many(sec, list(p.add_blocks(pub, blobs, blocks)))

    assert got == ["5", "5", "14", "5", "10"]


def test_a_repeated_index_is_added_again(key):
    """A block naming the same term twice means twice that term, not
    once. An implementation that deduplicates indices — plausible when
    the caller's blocks are row masks — silently halves a sum.
    """
    pub, sec = key
    blobs = encrypt(pub, [6.0])

    got = p.decrypt_many(sec, list(p.add_blocks(pub, blobs, [[0, 0, 0]])))

    assert got == ["18"]


def test_the_scale_travels_into_the_result(key):
    """The header of the sum is the header of its terms. Losing it makes
    `decrypt` divide by the wrong thing and return a plausible number.
    """
    pub, sec = key
    blobs = encrypt(pub, [1.5, 2.25], scale_pow10=8)

    total = bytes(p.add_blocks(pub, blobs, [[0, 1]])[0])

    assert p.decrypt(sec, total) == pytest.approx(3.75, abs=1e-7)


def test_no_blocks_is_no_sums(key):
    """A node with no candidates asks for nothing, and that is not an
    error. `add_many` refuses an EMPTY SUM, which is a different thing
    from an empty LIST of sums.
    """
    pub, _ = key
    blobs = encrypt(pub, [1.0])

    assert list(p.add_blocks(pub, blobs, [])) == []


def test_an_empty_block_is_refused_by_its_number(key):
    """Same answer as `add_many` to the same question: an empty sum has
    no encryption under this key. Returning a ciphertext of zero here
    would make the two functions disagree.

    The empty block is the SECOND one, so a refusal that fires on any
    empty input rather than on this block is distinguishable.
    """
    pub, _ = key
    blobs = encrypt(pub, [1.0, 2.0])

    with pytest.raises(ValueError) as refusal:
        p.add_blocks(pub, blobs, [[0, 1], []])

    assert "block #2" in str(refusal.value)
    assert "empty" in str(refusal.value)


def test_an_index_past_the_end_is_refused_by_block_and_position(key):
    """Out of range is the caller's own bookkeeping error, and it is
    worth locating: without the position, a block of thousands of row
    indices says only that one of them is wrong.
    """
    pub, _ = key
    blobs = encrypt(pub, [1.0, 2.0])

    with pytest.raises(ValueError) as refusal:
        p.add_blocks(pub, blobs, [[0], [0, 1, 7]])

    message = str(refusal.value)
    assert "block #2" in message
    assert "position 3" in message
    assert "only 2" in message


def test_mixing_scales_inside_a_block_is_refused(key):
    """Adding 1e0 to 1e8 adds different units. The scheme cannot see it:
    the sum goes through and a plausible wrong number comes back, so the
    refusal is the only place this can be caught.
    """
    pub, _ = key
    blobs = encrypt(pub, [1.0]) + encrypt(pub, [1.0], scale_pow10=8)

    with pytest.raises(ValueError) as refusal:
        p.add_blocks(pub, blobs, [[0, 1]])

    message = str(refusal.value)
    assert "block #1" in message
    assert "1e8" in message and "1e0" in message


def test_blocks_of_different_scales_are_each_allowed(key):
    """The refusal above is about ONE block. Two blocks at two scales are
    two separate sums, and a check written on a batch-wide accumulator
    would refuse them together.
    """
    pub, sec = key
    blobs = encrypt(pub, [2.0, 3.0]) + encrypt(pub, [1.5], scale_pow10=8)

    sums = list(p.add_blocks(pub, blobs, [[0, 1], [2]]))

    assert p.decrypt_many(sec, [bytes(sums[0])]) == ["5"]
    assert p.decrypt(sec, bytes(sums[1])) == pytest.approx(1.5, abs=1e-7)


def test_a_block_past_the_headroom_is_refused(key):
    """`add_many` caps a sum at `SUM_HEADROOM_TERMS` because past that
    the reserved headroom stops covering it. A per-CALL cap on a function
    that takes many sums would be the wrong cap: it has to be per block.

    The indices all name the same term, so this costs a list and no
    arithmetic — the length is checked before any of it.
    """
    pub, _ = key
    blobs = encrypt(pub, [1.0])

    with pytest.raises(ValueError) as refusal:
        p.add_blocks(pub, blobs, [[0] * (HEADROOM_TERMS + 1)])

    assert "block #1" in str(refusal.value)


def test_the_headroom_is_a_limit_and_not_a_wall_one_short_of_it(key):
    """The refusal above passes on an off-by-one that rejects a block of
    exactly `SUM_HEADROOM_TERMS`, which is allowed.
    """
    pub, sec = key
    blobs = encrypt(pub, [1.0])

    total = bytes(p.add_blocks(pub, blobs, [[0] * HEADROOM_TERMS])[0])

    assert p.decrypt_many(sec, [total]) == [str(HEADROOM_TERMS)]


def test_a_value_outside_the_group_is_refused_by_its_index(key):
    """Not a ciphertext under this key. The check is range-only, and it
    names the ciphertext rather than the block, because the input is
    wrong once no matter how many blocks name it.
    """
    pub, _ = key
    blobs = encrypt(pub, [1.0, 2.0])
    spoiled = blobs[1][:1] + bytes(len(blobs[1]) - 1)

    with pytest.raises(ValueError) as refusal:
        p.add_blocks(pub, [blobs[0], spoiled], [[0], [1]])

    assert "ciphertext #2" in str(refusal.value)


def test_a_ciphertext_no_block_names_is_never_read(key):
    """The refusal above must not reach an input nothing asks about.

    A loop over `add_many` never touches a blob outside the block it is
    summing, so a `add_blocks` that validates the whole array refuses
    calls the loop answers — which is the same function disagreeing with
    itself about an input neither reads. Found by review; the first
    version did exactly that.
    """
    pub, sec = key
    blobs = encrypt(pub, [1.0, 2.0])
    spoiled = blobs[1][:1] + bytes(len(blobs[1]) - 1)

    got = p.add_blocks(pub, [blobs[0], spoiled], [[0]])

    assert p.decrypt_many(sec, [bytes(got[0])]) == ["1"]


def test_no_blocks_reads_nothing_at_all(key):
    """The sharpest case of the rule above: with no blocks there is
    nothing to validate against, and an unreadable array is beside the
    point.
    """
    pub, _ = key
    spoiled = bytes(64)

    assert list(p.add_blocks(pub, [spoiled], [])) == []


def test_a_huge_index_is_reported_as_it_was_given(key):
    """`usize::MAX` is an ordinary Python integer, and the message used
    to add one to it: in release that wraps and names ciphertext `#0`,
    which is a real index and points the reader at the wrong term.
    """
    pub, _ = key
    blobs = encrypt(pub, [1.0, 2.0])
    huge = (1 << 64) - 1

    with pytest.raises(ValueError) as refusal:
        p.add_blocks(pub, blobs, [[huge]])

    message = str(refusal.value)
    assert str(huge) in message
    assert "#0" not in message
