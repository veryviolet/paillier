//! The Fermat threshold: the one constant that has already been wrong
//! twice, and that nothing guarded before this file existed.
//!
//! What is checked is not the value of the constant but its consequence:
//! a key the check refuses REALLY DOES factor by Fermat's method — right
//! here in the test, not by estimate. The number of steps at
//! `|p−q| = |p|/2 + k` is `≈ (p−q)²/(8√n) = 2^(|p|+2k)/2^(|p|+3) =
//! 2^(2k−3)` and does not depend on the key size at all: at `k = 8` that
//! is `2^13` steps whether the primes are 512 bits or 1536. Which is
//! exactly why the version with a threshold of `|p|/2 + 8` accepted a key
//! that factors in a few thousand steps.
//!
//! The second test is the other side: an ordinary key from two
//! independent safe primes must pass. Without it the threshold could be
//! "fixed" by refusing everything and the first test would stay green.

use paillier::keys::validate_private;
use rand::Rng;
use rug::integer::{IsPrime, Order};
use rug::Integer;

/// Half the modulus floor: anything shorter and `validate_private`
/// answers `ModulusTooShort` before it ever reaches the Fermat
/// threshold.
const PRIME_BITS: u32 = 1024;

fn random_odd(bits: u32) -> Integer {
    let mut rng = rand::thread_rng();
    let width = (bits / 8) as usize;
    let mut raw = vec![0u8; width];
    rng.fill(&mut raw[..]);
    raw[0] |= 0x80;
    let last = width - 1;
    raw[last] |= 1;
    Integer::from_digits(&raw, Order::MsfBe)
}

/// The nearest safe prime at or above `start`.
fn safe_prime_at_or_above(start: &Integer) -> Integer {
    let mut c = start.clone();
    loop {
        c.next_prime_mut();
        let half = Integer::from(&c - 1u32) / 2u32;
        if half.is_probably_prime(40) != IsPrime::No {
            return c;
        }
    }
}

/// Fermat's method. Returns a divisor and the number of steps taken.
fn fermat(n: &Integer, budget: u64) -> Option<(Integer, u64)> {
    let mut a = n.clone().sqrt();
    if Integer::from(&a * &a) < *n {
        a += 1;
    }
    for step in 0..budget {
        let b2 = Integer::from(&a * &a) - n;
        if b2.is_perfect_square() {
            let b = b2.sqrt();
            return Some((Integer::from(&a - &b), step));
        }
        a += 1;
    }
    None
}

#[test]
fn the_refused_key_really_does_factor_by_fermat() {
    let p = safe_prime_at_or_above(&random_odd(PRIME_BITS));

    // Aim at the boundary of the FORMER, wrong version: |p|/2 + 8 bits.
    let threshold_bits = PRIME_BITS / 2 + 8; // 264
    let gap = Integer::from(1) << (threshold_bits - 1); // 2^263, exactly 264 bits
    let margin = Integer::from(1) << 24; // headroom for the prime search step
    let target = Integer::from(&p - &gap) - margin;
    let q = safe_prime_at_or_above(&target);

    let diff = Integer::from(&p - &q).abs();
    println!("|p|      = {}", p.significant_bits());
    println!("|q|      = {}", q.significant_bits());
    println!(
        "|p-q|    = {} (former threshold {}, current {})",
        diff.significant_bits(),
        threshold_bits,
        PRIME_BITS - 100,
    );

    // 1. Such a key must NOW be refused.
    let verdict = validate_private(&p, &q);
    println!("validate_private: {verdict:?}");
    assert_eq!(
        verdict,
        Err(paillier::keys::KeyError::PrimesTooClose),
        "a key that Fermat factors in a few thousand steps must be refused",
    );

    // 2. And it really does factor by Fermat's method in those few
    //    thousand steps.
    let n = Integer::from(&p * &q);
    let started = std::time::Instant::now();
    let (factor, steps) = fermat(&n, 100_000_000).expect("Fermat must succeed");
    println!(
        "and it does factor in {} steps ({:?}) — which is why the refusal is right",
        steps,
        started.elapsed(),
    );
    assert!(factor == p || factor == q);
}

/// The safe prime nearest to `p − 2^gap_bits`.
fn safe_prime_at_gap(p: &Integer, gap_bits: u32) -> Integer {
    let gap = Integer::from(1) << (gap_bits - 1);
    let margin = Integer::from(1) << 24;
    safe_prime_at_or_above(&(Integer::from(p - &gap) - margin))
}

#[test]
fn the_threshold_is_pinned_by_number_on_both_sides() {
    // The two tests in this file used to admit a whole band of threshold
    // values: at `SLACK = 247` both stayed green, and the key they
    // accepted factored by Fermat in twenty-four thousand steps. Here the
    // threshold is pinned from both sides and no band is left.
    let threshold = PRIME_BITS - 100;
    let p = safe_prime_at_or_above(&random_odd(PRIME_BITS));

    let just_below = safe_prime_at_gap(&p, threshold - 1);
    let just_above = safe_prime_at_gap(&p, threshold + 1);

    let below_bits = Integer::from(&p - &just_below).abs().significant_bits();
    let above_bits = Integer::from(&p - &just_above).abs().significant_bits();
    println!("threshold {threshold}: below {below_bits}, above {above_bits}");
    assert!(
        below_bits < threshold,
        "the lower sample must be below the threshold"
    );
    assert!(
        above_bits >= threshold,
        "the upper sample must be at or above it"
    );

    assert_eq!(
        validate_private(&p, &just_below),
        Err(paillier::keys::KeyError::PrimesTooClose),
        "a difference one bit below the threshold must be refused",
    );
    assert!(
        validate_private(&p, &just_above).is_ok(),
        "a difference one bit above the threshold must be accepted",
    );
}

// The test "generate_keypair calls the key check" is NO LONGER here, and
// that is not a loss of coverage.
//
// It was structural — it read `src/lib.rs` and looked for the call in the
// text. Such a test passes straight through if the call is replaced by a
// comment with the same text (verified: the key assembles without a
// single prime check, and the suite reports 42 of 42), and goes red if
// the call is honestly moved into a helper. So it caught the wrong thing
// and punished the right one.
//
// The wiring is now guarded by the compiler: `validate_private` returns
// `keys::Validated`, which cannot be constructed outside the `keys`
// module, and `SecretKey` cannot be built without one. Skipping the check
// stopped compiling.

#[test]
fn a_normal_key_has_a_prime_gap_of_nearly_full_length() {
    // For contrast: two independent safe primes.
    let p = safe_prime_at_or_above(&random_odd(PRIME_BITS));
    let q = safe_prime_at_or_above(&random_odd(PRIME_BITS));
    let diff = Integer::from(&p - &q).abs();
    println!(
        "ordinary key: |p-q| = {} at |p| = {} (threshold {})",
        diff.significant_bits(),
        PRIME_BITS,
        PRIME_BITS - 100,
    );
    assert!(validate_private(&p, &q).is_ok());
}
