//! What exponent-secure powering costs, on our numbers.
//!
//! Decryption is slower than it could be, and that has to be explained
//! by measurement rather than from memory. There is exactly one
//! substantive difference: the two exponentiations in `secret::decrypt`
//! go through `mpz_powm_sec` rather than `mpz_powm`. `mpz_powm` is a
//! windowed exponentiation that indexes a table BY THE BITS of the
//! exponent — i.e. by the bits of `λ`, the long-lived secret of the key;
//! `mpz_powm_sec` reads the whole table at every step.
//!
//! Exactly that difference is measured and nothing else: the same base,
//! exponent and modulus as in the CRT components — an exponent `p−1` of
//! `|n|/2` bits, a modulus `p²` of `|n|` bits. The remaining steps of
//! decryption are identical in both variants and are not in the
//! measurement.
//!
//! Run: `cargo bench --bench secure_pow`.

use rug::Integer;
use std::time::Instant;

/// Repeats per point. One exponentiation at 2048 bits is about a
/// millisecond, so a hundred is enough, and the spread between runs
/// shows up across three independent series.
const ROUNDS: usize = 100;
const SERIES: usize = 3;

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    values[values.len() / 2]
}

/// Numbers of the right LENGTH rather than a real key: the cost of an
/// exponentiation depends on lengths, not on primality. Generating safe
/// primes would take seconds and add nothing to the measurement.
fn parameters(modulus_bits: u32) -> (Integer, Integer, Integer) {
    let half = modulus_bits / 2;
    let mut p = Integer::from(1u32) << (half - 1);
    p += 12345u32;
    p.set_bit(0, true);
    let p_square = Integer::from(&p * &p);
    let exponent = Integer::from(&p - 1u32);
    let base = (Integer::from(1u32) << (modulus_bits - 3)) + 6789u32;
    (base % &p_square, exponent, p_square)
}

fn main() {
    println!(
        "{:>7} {:>12} {:>12} {:>10}",
        "n bits", "powm, us", "powm_sec", "ratio"
    );
    for modulus_bits in [2048u32, 3072] {
        let (base, exponent, modulus) = parameters(modulus_bits);

        let mut plain = Vec::new();
        let mut secure = Vec::new();
        for _ in 0..SERIES {
            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ = base.clone().pow_mod(&exponent, &modulus).unwrap();
            }
            plain.push(started.elapsed().as_secs_f64() / ROUNDS as f64 * 1e6);

            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ = base.clone().secure_pow_mod(&exponent, &modulus);
            }
            secure.push(started.elapsed().as_secs_f64() / ROUNDS as f64 * 1e6);
        }

        let plain = median(plain);
        let secure = median(secure);
        println!(
            "{modulus_bits:>7} {plain:>12.1} {secure:>12.1} {:>10.2}",
            secure / plain
        );
    }
}
