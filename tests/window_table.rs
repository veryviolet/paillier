//! The window table must give EXACTLY what `pow_mod` gives.
//!
//! The technique is purely arithmetic: it does not change the result,
//! only the speed. So what has to be checked is equality of results, not
//! a round trip — a round trip stays green on a broken table if the
//! error is the same in encryption and decryption.
//!
//! The REAL code from `paillier::fast` is called. An earlier version of
//! this file assembled a copy of the implementation from its description
//! and therefore checked it against itself; the reference here is
//! `pow_mod` from GMP, an independent implementation of the same
//! exponentiation.

use paillier::fast::{build_window_table, pow_by_table, windows_for, windows_of};
use rug::integer::Order;
use rug::Integer;

/// The modulus to compute over. Small — the arithmetic does not depend
/// on the size, and the test should be fast.
fn fixture() -> (Integer, Integer) {
    let n = Integer::from(23u32) * 59u32;
    let nn = Integer::from(&n * &n);
    let hs = Integer::from(1234567u32) % nn.clone();
    (hs, nn)
}

#[test]
fn the_table_matches_pow_mod_on_every_two_byte_exponent() {
    // EXHAUSTIVELY over two bytes: 65536 exponents, every combination of
    // digits, including zeros in every position and runs of zeros.
    // Sampled values would miss exactly the error this test exists for —
    // a skipped or shifted window.
    let (hs, nn) = fixture();
    let table = build_window_table(&hs, &nn, 4);

    for value in 0u32..=0xffff {
        let raw = [(value >> 8) as u8, value as u8];
        let expected = hs
            .clone()
            .pow_mod(&Integer::from(value), &nn)
            .expect("pow_mod");
        let got = pow_by_table(&table, &windows_of(&raw));
        assert_eq!(got, expected, "exponent {value}");
    }
}

#[test]
fn the_table_matches_at_a_production_length_exponent() {
    // Two bytes will not catch an error that begins beyond them: an
    // overflowing window counter, a truncated table, sign extension.
    let (hs, nn) = fixture();
    let width = 128; // 1024 bits — as at a 2048-bit modulus
    let table = build_window_table(&hs, &nn, width * 2);

    for seed in 0u8..8 {
        let raw: Vec<u8> = (0..width)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
            .collect();
        let exponent = Integer::from_digits(&raw, Order::MsfBe);
        let expected = hs.clone().pow_mod(&exponent, &nn).expect("pow_mod");
        let got = pow_by_table(&table, &windows_of(&raw));
        assert_eq!(got, expected, "seed {seed}");
    }
}

#[test]
fn the_table_is_correct_with_multi_limb_entries() {
    // On the `fixture` modulus an entry fits in ONE 64-bit limb and the
    // stride along the row is one. An error in the stride — the most
    // likely error in constant-time reading — is indistinguishable from
    // its absence on such a modulus: `entry * width` at `width = 1`
    // equals `entry`.
    //
    // Here `n²` occupies five limbs, so the stride is checked honestly.
    let n = Integer::from(1u32) << 160u32;
    let n = n + 7u32;
    let nn = Integer::from(&n * &n);
    let hs = Integer::from(987654321u32);

    let table = build_window_table(&hs, &nn, 4);
    assert!(
        table.entry_width() >= 5,
        "the entry must span several limbs, and it spans {}",
        table.entry_width()
    );

    for value in 0u32..=0xffff {
        let raw = [(value >> 8) as u8, value as u8];
        let expected = hs
            .clone()
            .pow_mod(&Integer::from(value), &nn)
            .expect("pow_mod");
        let got = pow_by_table(&table, &windows_of(&raw));
        assert_eq!(got, expected, "exponent {value}");
    }
}

#[test]
fn a_zero_exponent_gives_one() {
    // The degenerate case, where every window selects the identity entry.
    //
    // Not "no multiplications happen": a multiplication happens at every
    // window precisely so that the time does not depend on the exponent.
    // What this checks is that the identity entry really is one — in
    // Montgomery form it is `R mod n²`, not the literal 1, and getting
    // that wrong would corrupt every ciphertext.
    let (hs, nn) = fixture();
    let table = build_window_table(&hs, &nn, 4);

    let got = pow_by_table(&table, &windows_of(&[0u8, 0u8]));

    assert_eq!(got, 1);
}

/// `windows_for` and `windows_of` must agree, and nothing in Rust made
/// them.
///
/// Their whole reason for existing as one function each is that the
/// table build and the exponent split have to produce the same count —
/// the docstring on `windows_for` says exactly that, and it used to be
/// `bytes * 2` in two places. Yet turning its ceiling into a floor
/// survived the entire Rust suite: no Rust test calls it, because the
/// tests above pass explicit window counts.
///
/// Python does catch it, but as a `PanicException` from inside the
/// extension — the `BaseException`-inheriting failure mode this library
/// works to avoid everywhere else. One assertion here closes it.
#[test]
fn the_window_count_matches_the_split() {
    for bytes in [1usize, 2, 3, 7, 8, 63, 64, 128, 129, 256] {
        assert_eq!(
            windows_of(&vec![0u8; bytes]).len(),
            windows_for(bytes),
            "{bytes} bytes: the table build and the exponent split disagree"
        );
    }
}

/// Both guards inside `pow_by_table` had no test at all, and deleting
/// either survived the suite. Their own comments explain why they exist:
/// an out-of-range digit matches no entry in the masked read and yields a
/// silent ZERO rather than a refusal — the exact failure they prevent,
/// unchecked.
///
/// `windows_of` cannot produce either input: it emits six-bit digits and
/// as many of them as the exponent has windows. So the digits are built
/// by hand, which is the point — the guards exist for a caller that is
/// not `windows_of`.
#[test]
#[should_panic(expected = "does not fit")]
fn a_digit_outside_the_window_is_refused() {
    let (hs, nn) = fixture();
    let table = build_window_table(&hs, &nn, 4);

    // 64 is one past the last entry of a six-bit row.
    let _ = pow_by_table(&table, &[1u8, 64u8, 3u8]);
}

#[test]
#[should_panic(expected = "the table has")]
fn more_digits_than_windows_is_refused() {
    let (hs, nn) = fixture();
    let table = build_window_table(&hs, &nn, 4);

    let _ = pow_by_table(&table, &[1u8, 2u8, 3u8, 4u8, 5u8]);
}
