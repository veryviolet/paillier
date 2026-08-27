//! What orders `hs` can have when the primes are safe.
//!
//! Short-exponent security rests on this: a smooth order makes
//! Pohlig–Hellman cheap, and the `2^(|r|/2)` margin stops meaning
//! anything (`docs/short-exponent-security.md`).
//!
//! # Why the set of orders is exactly `{2, 2p′, 2q′, 2p′q′}`
//!
//! This is a consequence, not an observation. With safe `p = 2p′+1` and
//! `q = 2q′+1` the group is `Z*_n ≅ Z_{2p′} × Z_{2q′}`, and `hs = h^n`.
//! In `Z*_{n²} ≅ Z*_{p²} × Z*_{q²}` raising to the power `n = pq` leaves
//! component orders dividing `2p′` and `2q′`, so
//! `ord(hs) | lcm(2p′, 2q′) = 2p′q′`. The divisors of `2p′q′` are
//! `1, 2, p′, q′, 2p′, 2q′, p′q′, 2p′q′`; the odd ones drop out because
//! `h = −x²` has even order, and `1` and `2` are filtered by
//! `DegenerateHs`.
//!
//! The argument does not depend on the key length. Hence two tests
//! rather than one: exhaustive on a TOY key, where enumerating every `x`
//! is possible, and sampled on a real one, where no machine could.
//!
//! # What is being corrected here
//!
//! The document used to say: "an exhaustive sweep of all `x` on five
//! REAL keys gave orders exactly from `{2, 2p′, 2q′, 2p′q′}`". An
//! exhaustive sweep of `Z*_n` at `|n| ≥ 2048` is impossible, and there
//! was no artefact behind that sentence in the repository — nor behind
//! the "200 of 200" and "400 of 400" in the neighbouring paragraphs. The
//! claim was true; the evidence was invented.

use paillier::keys::{derive_h, derive_hs, KeyError};
use paillier::primes::safe_prime;
use rug::Integer;

/// The order of `value` in `Z*_{n²}`, given the factorisation
/// `λ = 2·p′·q′`.
///
/// Descent through the divisors: start at `λ` and divide by each prime
/// while the power stays neutral.
fn order_of(value: &Integer, nn: &Integer, p_half: &Integer, q_half: &Integer) -> Integer {
    let mut order = Integer::from(2u32) * p_half * q_half;
    for divisor in [Integer::from(2u32), p_half.clone(), q_half.clone()] {
        loop {
            let reduced = Integer::from(&order / &divisor);
            if Integer::from(&order % &divisor) != 0
                || value.clone().pow_mod(&reduced, nn).expect("pow_mod") != 1
            {
                break;
            }
            order = reduced;
        }
    }
    order
}

/// `p = 2·11+1 = 23`, `q = 2·29+1 = 59`: `n = 1357`, `Z*_n` has exactly
/// `φ(n) = 1276` elements, and the sweep is HONESTLY exhaustive.
///
/// The pair is the same as in `tests/degenerate_x.rs`, and that matters.
/// It used to be `q = 47` — and there `q − 1 = 2·23`, so `p` divides
/// `λ`, `gcd(λ, n) = 23`, `µ = λ⁻¹ mod n` does not exist and the scheme
/// does not work at all. Worse: the map `h ↦ h^n mod n²` stops being
/// injective, and that is the CENTRAL step of the argument above. The
/// claim `ord(hs) | 2p′q′` held there too, but nine tenths of the
/// refusals this test counts were an artefact of a broken fixture rather
/// than behaviour of the scheme.
///
/// The neighbouring file had already abandoned this pair and written
/// down why. I brought it back without reading that — and evidence taken
/// on an unfit fixture is evidence about the fixture.
#[test]
fn exhaustively_on_a_toy_key() {
    let (p, q) = (Integer::from(23u32), Integer::from(59u32));
    let p_half = Integer::from(11u32);
    let q_half = Integer::from(29u32);
    let n = Integer::from(&p * &q);
    let nn = Integer::from(&n * &n);

    let allowed = [
        Integer::from(2u32) * &p_half,
        Integer::from(2u32) * &q_half,
        Integer::from(2u32) * &p_half * &q_half,
    ];

    let mut checked = 0usize;
    let mut rejected = 0usize;
    let mut x = Integer::from(2u32);
    let top = Integer::from(&n - 2u32);
    while x <= top {
        match derive_h(&x, &n).and_then(|h| derive_hs(&h, &n)) {
            Ok(hs) => {
                let order = order_of(&hs, &nn, &p_half, &q_half);
                assert!(
                    allowed.contains(&order),
                    "x = {x} gave order {order}, which is not in the set"
                );
                checked += 1;
            }
            // `BadX` — not coprime; `DegenerateHs` — order ≤ 2, exactly
            // the degeneracy the check exists to catch.
            Err(KeyError::BadX) | Err(KeyError::DegenerateHs) => rejected += 1,
            Err(other) => panic!("unexpected error at x = {x}: {other:?}"),
        }
        x += 1u32;
    }

    // An assertion of absence passes on emptiness: if `derive_h` refused
    // everything, the loop would check no order at all and the test would
    // still be green. Hence two counters and both sides.
    //
    // The threshold is not invented: the sweep runs over `x ∈ [2, n−2]`,
    // and what is refused are the multiples of `p` or `q` (that is
    // `p + q − 2` values) plus those where `h = −1`. On a sound fixture
    // there are exactly two degenerate ones, so about six percent are
    // refused. Eighty is headroom for a change in `derive_h` that still
    // fails if it starts refusing everything.
    let total = checked + rejected;
    let expected: usize = (Integer::from(&n - 3u32)).to_usize().expect("it fits");
    assert_eq!(total, expected, "the sweep skipped part of the range");
    assert!(
        checked * 100 >= total * 80,
        "accepted {checked} of {total} — the order check saw almost nothing"
    );
    assert!(
        rejected > 0,
        "not a single value was refused, which is suspicious"
    );
}

/// At real lengths a sweep is impossible, so this is a sample — and it
/// says which one.
#[test]
fn sampled_on_keys_of_the_real_construction() {
    // 256-bit primes: the construction is the one used at 1024, and the
    // run fits in seconds. The argument above does not depend on the
    // length, and that is checked separately by one production-length key
    // below.
    const KEYS: usize = 12;
    let mut full = 0usize;
    for _ in 0..KEYS {
        let p = safe_prime(256);
        let q = safe_prime(256);
        if p == q {
            continue;
        }
        let p_half = Integer::from(&p - 1u32) / 2u32;
        let q_half = Integer::from(&q - 1u32) / 2u32;
        let n = Integer::from(&p * &q);
        let nn = Integer::from(&n * &n);

        let mut x = Integer::from(3u32);
        let hs = loop {
            match derive_h(&x, &n).and_then(|h| derive_hs(&h, &n)) {
                Ok(hs) => break hs,
                _ => x += 1u32,
            }
        };
        let order = order_of(&hs, &nn, &p_half, &q_half);
        let lambda = Integer::from(2u32) * &p_half * &q_half;
        if order == lambda {
            full += 1;
        }
    }
    assert_eq!(full, KEYS, "{full} keys of {KEYS} gave the full λ");
}

/// One key of production length, so that "the argument does not depend
/// on the length" is not left as words.
#[test]
fn one_key_of_production_length() {
    let p = safe_prime(1024);
    let q = safe_prime(1024);
    let p_half = Integer::from(&p - 1u32) / 2u32;
    let q_half = Integer::from(&q - 1u32) / 2u32;
    let n = Integer::from(&p * &q);
    let nn = Integer::from(&n * &n);

    let mut x = Integer::from(3u32);
    let hs = loop {
        match derive_h(&x, &n).and_then(|h| derive_hs(&h, &n)) {
            Ok(hs) => break hs,
            _ => x += 1u32,
        }
    };

    assert_eq!(
        order_of(&hs, &nn, &p_half, &q_half),
        Integer::from(2u32) * &p_half * &q_half
    );
}
