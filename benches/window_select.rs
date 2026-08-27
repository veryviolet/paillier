//! What the constant-time table costs — the WHOLE of it.
//!
//! Two exponentiations side by side on the same `hs`, `n²` and exponent:
//!
//! * **old** — `Vec<Vec<Integer>>` with the entry taken as `row[digit]`,
//!   so the memory address depends on the secret digit, and ordinary
//!   `mpz` arithmetic, so the cost depends on the value;
//! * **new** — `fast::pow_by_table`: a row of limbs read in full with the
//!   wanted entry folded out by an arithmetic mask, over fixed-width
//!   Montgomery arithmetic.
//!
//! Read what this measures precisely. It is **not** the isolated price
//! of the masked read: the new arm also changed the arithmetic. The
//! isolated figure — **1–5 %** for the mask — was measured when both arms
//! were `mpz`, and it stands as a historical measurement; the middle
//! variant does not exist in the code any more, and rebuilding it here
//! would mean benchmarking a copy written from a description.
//!
//! What this measures now is the two states of the library, which is the
//! number that belongs in the changelog.
//!
//! The reason the cache channel stayed open for so long is worth keeping.
//! The docstring said: "reading the whole row at every window means
//! paying sixteen times over". That conflates two things. There is still
//! exactly ONE multiplication on 4096 bits; what is added is a streaming
//! read of the row.
//!
//! The results are checked for equality: a benchmark whose two branches
//! compute different things compares nothing.
//!
//! Run: `cargo bench --bench window_select`.

use paillier::fast::{build_window_table, pow_by_table, windows_for, windows_of, WINDOW_BITS};
use rug::Integer;
use std::time::Instant;

const ROUNDS: usize = 20;
const SERIES: usize = 5;

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    values[values.len() / 2]
}

/// The old layout: entries as `Integer`, selection by index, `mpz`
/// arithmetic throughout.
fn build_indexed(hs: &Integer, nn: &Integer, windows: usize) -> Vec<Vec<Integer>> {
    let width = 1usize << WINDOW_BITS;
    let mut table = Vec::with_capacity(windows);
    let mut base = hs.clone();
    for _ in 0..windows {
        let mut row = Vec::with_capacity(width);
        row.push(Integer::from(nn + 1u32));
        let mut value = base.clone();
        row.push(value.clone());
        for _ in 2..width {
            value = value * &base % nn;
            row.push(value.clone());
        }
        table.push(row);
        for _ in 0..WINDOW_BITS {
            base = base.clone().square() % nn;
        }
    }
    table
}

fn pow_indexed(table: &[Vec<Integer>], digits: &[u8], nn: &Integer) -> Integer {
    let mut result = Integer::from(1);
    for (window, digit) in digits.iter().enumerate() {
        result = result * &table[window][*digit as usize] % nn;
    }
    result
}

/// Numbers of the right LENGTH: the cost of reading and multiplying
/// depends on lengths, not on whether this is a real key.
fn parameters(modulus_bits: u32) -> (Integer, Integer) {
    let mut n = Integer::from(1u32) << (modulus_bits - 1);
    n += 54321u32;
    n.set_bit(0, true);
    let nn = Integer::from(&n * &n);
    let hs = (Integer::from(1u32) << (modulus_bits + 7)) + 13579u32;
    (hs % &nn, nn)
}

fn main() {
    println!(
        "{:>7} {:>8} {:>14} {:>14} {:>10}",
        "n bits", "rows", "old, us", "new, us", "ratio"
    );
    for modulus_bits in [2048u32, 3072] {
        let (hs, nn) = parameters(modulus_bits);
        let exponent_bytes = (modulus_bits / 2 / 8) as usize;
        // Through the same function the production path uses. This
        // used to be `exponent_bytes * 2` — the formula for a four-bit
        // window — and the benchmark built a table one and a half times
        // larger than production: 8.4 MB instead of 5.6 at 2048 bits,
        // 18.9 instead of 12.6 at 3072. The second is worse: 18.9 MB
        // crosses the 16 MB L3 boundary, precisely the one the choice of
        // six is justified by. So the cost of constant-time reading was
        // published as measured on a structure the library never builds.
        let windows = windows_for(exponent_bytes);

        let indexed = build_indexed(&hs, &nn, windows);
        let masked = build_window_table(&hs, &nn, windows);

        let raw: Vec<u8> = (0..exponent_bytes).map(|i| (i * 37 + 11) as u8).collect();
        let digits = windows_of(&raw);

        assert_eq!(
            pow_indexed(&indexed, &digits, &nn),
            pow_by_table(&masked, &digits),
            "the two layouts compute different things — nothing to compare"
        );

        let mut by_index = Vec::new();
        let mut by_mask = Vec::new();
        for _ in 0..SERIES {
            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ = pow_indexed(&indexed, &digits, &nn);
            }
            by_index.push(started.elapsed().as_secs_f64() / ROUNDS as f64 * 1e6);

            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ = pow_by_table(&masked, &digits);
            }
            by_mask.push(started.elapsed().as_secs_f64() / ROUNDS as f64 * 1e6);
        }

        let by_index = median(by_index);
        let by_mask = median(by_mask);
        println!(
            "{modulus_bits:>7} {windows:>8} {by_index:>14.1} {by_mask:>14.1} {:>10.2}",
            by_mask / by_index
        );
    }
}
