//! `x = 1` must be refused.
//!
//! It passes both `gcd(x, n) = 1` and the Jacobi-symbol check — with Blum
//! primes `jacobi(−1, p) = jacobi(−1, q) = −1`. It gives `h = −1` and
//! `hs = n²−1`, and `hs^r` then takes exactly two values. The round trip
//! and the homomorphism are still correct, and an observer who knows only
//! `n` reads the plaintext out of any ciphertext.

use paillier::keys::{derive_h, derive_h_checked, derive_hs, KeyError};
use rug::Integer;

/// A small but **valid** Paillier modulus.
///
/// `p = 2·11+1 = 23`, `q = 2·29+1 = 59` — both safe primes, both
/// `≡ 3 (mod 4)`, `gcd(p−1, q−1) = 2`, and, decisively here,
/// `gcd(λ, n) = 1`, so `µ = λ⁻¹ mod n` exists and decryption is defined.
///
/// It used to be `q = 47`. There `q − 1 = 2·23`, so `p` divides `λ`,
/// `gcd(λ, n) = 23`, and `µ` does not exist at all:
/// `DecryptionKey::from_primes` would refuse such a key. The scheme does
/// not work on it, and the map `h ↦ h^n mod n²` stops being injective —
/// degenerate `x` turn out to be 90 in a thousand there instead of two.
/// That is, the fixture distorted exactly the behaviour this file checks.
fn small_key() -> (Integer, Integer, Integer) {
    let p = Integer::from(23);
    let q = Integer::from(59);
    let n = Integer::from(&p * &q);
    (p, q, n)
}

#[test]
fn one_is_refused_before_hs_is_derived() {
    let (_, _, n) = small_key();

    assert_eq!(derive_h(&Integer::from(1), &n), Err(KeyError::BadX));
}

#[test]
fn zero_and_the_upper_bound_are_refused_by_range() {
    let (_, _, n) = small_key();

    assert_eq!(derive_h(&Integer::from(0), &n), Err(KeyError::BadX));
    // `x = n−1` gives the same `h = −1` as one does.
    let top = Integer::from(&n - 1u32);
    assert_eq!(derive_h(&top, &n), Err(KeyError::BadX));
}

#[test]
fn the_sign_check_is_green_on_one_and_therefore_not_a_defence() {
    // This is what the test exists for: to show that the Jacobi symbol
    // catches nothing here, and that the only defence is narrowing the
    // range.
    let (p, q, n) = small_key();
    let h_minus_one = Integer::from(&n - 1u32);

    assert_eq!(h_minus_one.jacobi(&p), -1);
    assert_eq!(h_minus_one.jacobi(&q), -1);
}

#[test]
fn second_line_of_defence_fires_on_real_input() {
    // Non-trivial square roots of one: `x² ≡ 1 (mod n)` with
    // `x ∉ {1, n−1}`. Such an `x` passes the range, the `gcd` and the
    // Jacobi symbol — and degenerates only at `hs`. So the second line is
    // not "just in case": it catches input that every earlier check
    // accepts.
    let (p, q, n) = small_key();
    let limit = n.to_u32().unwrap();

    let mut found = 0;
    for candidate in 2..(limit - 1) {
        let x = Integer::from(candidate);
        if Integer::from(&x * &x) % &n != 1 {
            continue;
        }
        found += 1;
        // Every earlier check passes…
        let h = derive_h_checked(&x, &p, &q, &n)
            .expect("a non-trivial root must pass the range and Jacobi checks");
        // …and only deriving `hs` catches the degeneracy.
        assert_eq!(derive_hs(&h, &n), Err(KeyError::DegenerateHs));
    }
    assert!(
        found > 0,
        "no non-trivial roots were found — the fixture is the wrong one"
    );
}

#[test]
fn degenerate_hs_is_refused_even_when_planted_by_hand() {
    let (_, _, n) = small_key();

    // `h = −1` — what `x = 1` would have given had the range not been
    // narrowed.
    assert_eq!(
        derive_hs(&Integer::from(&n - 1u32), &n),
        Err(KeyError::DegenerateHs),
    );
    // And `h = 1`: `hs = 1` gives exactly `c = 1 + m·n`, i.e. it removes
    // the randomisation entirely.
    assert_eq!(derive_hs(&Integer::from(1), &n), Err(KeyError::DegenerateHs));
}

#[test]
fn a_usable_x_passes_or_the_refusals_above_mean_nothing() {
    let (p, q, n) = small_key();
    let limit = n.to_u32().unwrap();

    let mut accepted = 0;
    for candidate in 2..(limit - 1) {
        let x = Integer::from(candidate);
        if let Ok(h) = derive_h_checked(&x, &p, &q, &n) {
            if derive_hs(&h, &n).is_ok() {
                accepted += 1;
            }
        }
    }
    assert!(
        accepted > 0,
        "not a single x was accepted — the refusals above mean nothing"
    );
}
