//! What shortening the exponent would buy — by measurement, not by
//! mental arithmetic.
//!
//! `docs/short-exponent-security.md` used to say that the `|n|/2`
//! exponent is four times longer than needed and that shortening it to
//! 256 bits would lift single-threaded encryption "from about 683 to
//! 2600 ops/s". That number followed from nothing: linearity in the
//! window count had been measured, but the constant overhead — encoding,
//! `1 + m·n`, the multiplication, serialisation — was left out of the
//! calculation, and it is what the result runs into once the exponent
//! shrinks.
//!
//! What is measured here is exactly what depends on exponent length:
//! the time of `pow_by_table` at 1024, 512 and 256 bits. Everything
//! else in encryption is independent of it, so the total follows by
//! adding the constant part, which `benches/measure.py` measures.
//!
//! Run: `cargo bench --bench exponent_length`.

use paillier::fast::{build_window_table, pow_by_table, windows_for, windows_of};
use rug::Integer;
use std::time::Instant;

const ROUNDS: usize = 20;
const SERIES: usize = 5;

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    values[values.len() / 2]
}

fn parameters(modulus_bits: u32) -> (Integer, Integer) {
    let mut n = Integer::from(1u32) << (modulus_bits - 1);
    n += 54321u32;
    n.set_bit(0, true);
    let nn = Integer::from(&n * &n);
    let hs = (Integer::from(1u32) << (modulus_bits + 7)) + 13579u32;
    (hs % &nn, nn)
}

fn main() {
    let modulus_bits = 2048u32;
    let (hs, nn) = parameters(modulus_bits);

    println!("modulus {modulus_bits} bits");
    println!(
        "{:>16} {:>7} {:>14}",
        "exponent bits", "windows", "pow_by_table"
    );

    let mut measured = Vec::new();
    for exponent_bits in [1024usize, 512, 256] {
        let exponent_bytes = exponent_bits / 8;
        // Through the same function the production path uses. This
        // used to be `exponent_bytes * 2` — a formula correct only at
        // `WINDOW_BITS = 4`; at six it printed twice as many windows as
        // were actually walked.
        let windows = windows_for(exponent_bytes);
        let table = build_window_table(&hs, &nn, windows);
        let raw: Vec<u8> = (0..exponent_bytes).map(|i| (i * 37 + 11) as u8).collect();
        let digits = windows_of(&raw);

        let mut taken = Vec::new();
        for _ in 0..SERIES {
            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ = pow_by_table(&table, &digits);
            }
            taken.push(started.elapsed().as_secs_f64() / ROUNDS as f64 * 1e6);
        }
        let taken = median(taken);
        println!("{exponent_bits:>16} {windows:>7} {taken:>11.1} us");
        measured.push((exponent_bits, taken));
    }

    // The constant part of encryption does not depend on exponent
    // length, but it is what sets the ceiling once the exponent shrinks.
    // `benches/measure.py` measures it (full sequential encryption minus
    // `pow_by_table` at a 1024-bit exponent) and supplies it as a
    // number rather than a guess.
    println!(
        "\ntotal time = pow_by_table + the constant part;\n\
         the constant part cannot be measured here — see `measure.py`."
    );
    let full = measured[0].1;
    for (bits, taken) in &measured {
        println!(
            "{bits:>5} bits: share of the current full exponentiation — {:.2}",
            taken / full
        );
    }
}
