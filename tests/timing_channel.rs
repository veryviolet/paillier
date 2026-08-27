//! Exponentiation time must not depend on the SECRET exponent.
//!
//! Two channels, measured separately because they can mask each other:
//! the WEIGHT of the exponent (how many digits are non-zero) and the
//! POSITION of the non-zero digits (how many leading zeros there are).
//!
//! These are TESTS, not benchmarks, and the difference matters. The
//! check used to live in `benches/`, i.e. it ran by hand and printed a
//! number for a human to read. That is exactly how the regression it was
//! supposed to catch got through: substituting one into the table made
//! the run 0.6 % more expensive instead of the expected 6.7 %, and that
//! was read as good news rather than as work not being done. Putting the
//! same action on guard duty means guarding a defect with its own cause.
//!
//! The signal is the SLOPE of time against the parameter, not the
//! absolute time: absolute time depends on the machine, the slope does
//! not. Where the threshold comes from, measured on both sides, is at
//! `WEIGHT_SLOPE_LIMIT` and `POSITION_SLOPE_LIMIT`. They differ, and
//! why is written at each.

use paillier::fast::{build_window_table, pow_by_table, WindowTable};
use rug::Integer;
use std::time::Instant;

const WINDOWS: usize = 256;

/// How many DIFFERENT digits to cycle through. This used to be 15 — the
/// whole range at a four-bit window and a quarter of it at six bits. A
/// constant-time check has to touch the whole row, or three quarters of
/// the entries never enter the measurement.
const ROW_SPAN: usize = 1 << paillier::fast::WINDOW_BITS;

/// Repeats per point. Neighbouring measurements differ by up to 15 %,
/// while the leak signal over the whole range was about 1200 µs; a
/// median of nine runs of thirty removes the outliers without making the
/// test noticeably longer. Nine and not five: at five the residual slope
/// wandered over −1.01…+0.77 across eight runs, which is most of the
/// threshold.
const ROUNDS: usize = 30;
const REPEATS: usize = 9;
/// Slope threshold for the WEIGHT channel, µs per non-zero digit.
///
/// Unchanged at 1.0, and deliberately so. Collapsing both channels onto
/// one number was tried and reverted: a single 2.5 tightens the position
/// test and quietly LOOSENS this one, which is a regression dressed up
/// as a simplification.
///
/// The residual measured over twelve clean runs spans −0.53…+0.37 —
/// about half the threshold. An earlier draft of this comment claimed
/// 0.08–0.23 from four runs, which understated the spread by a factor
/// of two: four runs do not measure a noise envelope. The threshold
/// stands, the quoted band did not.
const WEIGHT_SLOPE_LIMIT: f64 = 1.0;

/// Slope threshold for the POSITION channel, µs per leading zero.
///
/// It used to be 15.0, because that channel was open and the test only
/// asked that it not GROW. Now that it is closed, a loose threshold is
/// worse than none: at 15.0 this file stayed green under a mutation that
/// reintroduced a branch on the secret digit and drove the slope to
/// −4.58.
///
/// Where 2.5 comes from — measured on both sides, not chosen:
///
/// * NOISE. Eight clean runs at `REPEATS = 9` gave residual slopes in
///   −0.98…+0.65. The threshold sits 2.6× above the worst of them.
/// * SIGNAL. The historical leak was −6.33 µs per zero; the branch
///   mutation reproduces −4.0…−4.8. The threshold sits 1.6× below the
///   weakest of those.
///
/// Why this one is looser than the weight threshold: the position
/// measurement is noisier. It varies how many leading windows select the
/// identity entry, while the weight measurement spreads its non-zero
/// digits evenly and keeps the run length the same. A threshold of 1.0
/// here would flake — one of eight clean runs at `REPEATS = 5` came out
/// at −1.012.
const POSITION_SLOPE_LIMIT: f64 = 2.5;

/// Exactly `count` non-zero digits, spread EVENLY over the whole length.
///
/// The earlier version took `i % step == 0`, and at `count = 192` the
/// step came out as one: 256 non-zero digits instead of 192, two of the
/// four points coincided, and the slope was fitted over a degenerate
/// set.
fn digits_with_weight(count: usize) -> Vec<u8> {
    (0..WINDOWS)
        .map(|i| {
            let before = i * count / WINDOWS;
            let after = (i + 1) * count / WINDOWS;
            if after > before {
                ((i % (ROW_SPAN - 1)) + 1) as u8
            } else {
                0
            }
        })
        .collect()
}

/// The modulus to measure against. The primes are FAR apart — not
/// because that matters for timing, but so the fixture cannot be copied
/// as a model key: close primes factor by Fermat's method, and
/// `keys::validate_private` refuses such a key.
fn modulus() -> Integer {
    let mut p = (Integer::from(1) << 1024u32) + 1u32;
    p.next_prime_mut();
    let mut q = (Integer::from(1) << 900u32) + 4321u32;
    q.next_prime_mut();
    let n = Integer::from(&p * &q);
    Integer::from(&n * &n)
}

fn measure(table: &WindowTable, digits: &[u8]) -> f64 {
    // Warm-up: the first call pays for the cache misses.
    let _ = pow_by_table(table, digits);
    let mut taken: Vec<f64> = Vec::with_capacity(REPEATS);
    for _ in 0..REPEATS {
        let started = Instant::now();
        let mut guard = Integer::from(0);
        for _ in 0..ROUNDS {
            guard += pow_by_table(table, digits).significant_bits();
        }
        assert!(guard > 0);
        taken.push(started.elapsed().as_secs_f64() * 1e6 / ROUNDS as f64);
    }
    taken.sort_by(|a, b| a.partial_cmp(b).expect("time is never NaN"));
    taken[REPEATS / 2]
}

/// Least squares over the points `(parameter, µs)`.
fn slope(points: &[(f64, f64)]) -> f64 {
    let count = points.len() as f64;
    let mean_x = points.iter().map(|p| p.0).sum::<f64>() / count;
    let mean_y = points.iter().map(|p| p.1).sum::<f64>() / count;
    let top: f64 = points.iter().map(|p| (p.0 - mean_x) * (p.1 - mean_y)).sum();
    let bottom: f64 = points.iter().map(|p| (p.0 - mean_x).powi(2)).sum();
    top / bottom
}

#[test]
fn time_does_not_depend_on_exponent_weight() {
    let nn = modulus();
    let hs = Integer::from(&nn / 3u32) + 7u32;
    let table = build_window_table(&hs, &nn, WINDOWS);

    // The non-zero digits are SPREAD over the whole length rather than
    // pushed to the front: otherwise the weight is not the only thing
    // that changes — so does the number of leading zeros, and one channel
    // masks the other. That is precisely how the earlier version of this
    // file overlooked the position leak.
    let mut points = Vec::new();
    for count in [64usize, 128, 192, 256] {
        let digits = digits_with_weight(count);
        let actual = digits.iter().filter(|d| **d != 0).count();
        assert_eq!(actual, count, "the weight must be exactly what was asked");
        points.push((actual as f64, measure(&table, &digits)));
    }

    let found = slope(&points);
    for (count, spent) in &points {
        println!("non-zero {count:>4} of {WINDOWS}   {spent:9.1} us");
    }
    println!("slope against weight: {found:.3} us per digit (limit {WEIGHT_SLOPE_LIMIT})");

    assert!(
        found.abs() < WEIGHT_SLOPE_LIMIT,
        "time depends on the weight of the exponent: slope {found:.3} us per \
         digit. This has leaked here twice already: first by skipping zero \
         digits, then by substituting a SINGLE-LIMB one instead of a \
         full-width residue",
    );
}

#[test]
fn time_does_not_depend_on_leading_zeros() {
    // This channel was OPEN and is now closed. The loop used to start
    // from an `Integer` equal to one, which occupies a single limb, so
    // while the low digits were zero the accumulator stayed cheap to
    // multiply by: −6.33 µs per leading zero.
    //
    // What closed it is `crate::mont` — the accumulator now lives in a
    // fixed-width limb buffer, where no value is cheaper than another.
    // Measured after the change: −0.201, thirty-one times smaller and
    // indistinguishable from the weight channel's 0.023.
    //
    // The obvious cure did NOT work and was tried: starting from `n² + 1`
    // gave −6.56, because `%` returns the canonical residue and after the
    // first reduction the accumulator is one again. While a value is
    // CONGRUENT to one, `mpz` represents it as one.
    let nn = modulus();
    let hs = Integer::from(&nn / 3u32) + 7u32;
    let table = build_window_table(&hs, &nn, WINDOWS);

    let mut points = Vec::new();
    for leading in [0usize, 16, 32, 64] {
        let digits: Vec<u8> = (0..WINDOWS)
            .map(|i| if i < leading { 0 } else { ((i % (ROW_SPAN - 1)) + 1) as u8 })
            .collect();
        points.push((leading as f64, measure(&table, &digits)));
    }

    let found = slope(&points);
    for (leading, spent) in &points {
        println!("leading zeros {leading:>3}   {spent:9.1} us");
    }
    println!("slope against position: {found:.3} us per zero (limit {POSITION_SLOPE_LIMIT})");

    assert!(
        found.abs() < POSITION_SLOPE_LIMIT,
        "time depends on where the non-zero digits sit: slope {found:.3} us \
         per leading zero. Before Montgomery form this was −6.33, and the \
         threshold here was 15.0 — which is why it stayed green through it",
    );
}
