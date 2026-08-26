//! What a multiplication modulo `n²` costs — and whether Montgomery
//! is worth it.
//!
//! A separate benchmark, because the Montgomery decision was once taken
//! on a measurement of ENCRYPTION ONLY, and that was a mistake: there
//! the window table ate everything. Addition is a different operation
//! with a different profile, and a conclusion cannot be carried from
//! one to the other.
//!
//! Run: `cargo bench --bench modmul`.

use rug::Integer;
use std::time::Instant;

const ROUNDS: usize = 20_000;

/// REDC over `rug::Integer` — exactly the one that was removed.
struct Montgomery {
    modulus: Integer,
    bits: u32,
    inverse: Integer,
    r_squared: Integer,
}

impl Montgomery {
    fn new(modulus: &Integer) -> Self {
        let bits = (modulus.significant_bits() + 63) / 64 * 64;
        let r = Integer::from(1) << bits;
        let inverse = Integer::from(&r) - modulus.clone().invert(&r).expect("odd modulus");
        let r_squared = (Integer::from(1) << (2 * bits)) % modulus;
        Self { modulus: modulus.clone(), bits, inverse, r_squared }
    }

    fn reduce(&self, value: Integer) -> Integer {
        let low = value.clone().keep_bits(self.bits);
        let m = (low * &self.inverse).keep_bits(self.bits);
        let result = (value + m * &self.modulus) >> self.bits;
        if result >= self.modulus { result - &self.modulus } else { result }
    }

    fn multiply(&self, left: &Integer, right: &Integer) -> Integer {
        self.reduce(Integer::from(left * right))
    }

    fn enter(&self, value: &Integer) -> Integer {
        self.reduce(Integer::from(value * &self.r_squared))
    }
}

fn modulus_of(bits: u32) -> Integer {
    let mut n = (Integer::from(1) << (bits / 2)) + 1u32;
    n.next_prime_mut();
    let mut q = (Integer::from(1) << (bits / 2)) + 12345u32;
    q.next_prime_mut();
    Integer::from(&n * &q)
}

fn main() {
    for key_bits in [2048u32, 3072] {
        let n = modulus_of(key_bits);
        let nn = Integer::from(&n * &n);
        println!("\n=== key modulus {key_bits} bits, n² = {} bits ===", nn.significant_bits());

        let a = Integer::from(&nn / 3u32) + 7u32;
        let b = Integer::from(&nn / 5u32) + 11u32;

        let started = Instant::now();
        let mut acc = a.clone();
        for _ in 0..ROUNDS {
            acc = acc * &b % &nn;
        }
        let plain = started.elapsed();
        println!(
            "plain    a·b mod n²   {:8.3?}  {:6.2} us/op",
            plain,
            plain.as_secs_f64() * 1e6 / ROUNDS as f64,
        );

        let space = Montgomery::new(&nn);
        let bm = space.enter(&b);
        let started = Instant::now();
        let mut acc_m = space.enter(&a);
        for _ in 0..ROUNDS {
            acc_m = space.multiply(&acc_m, &bm);
        }
        let mont = started.elapsed();
        println!(
            "Montgomery            {:8.3?}  {:6.2} us/op   ratio {:.2}",
            mont,
            mont.as_secs_f64() * 1e6 / ROUNDS as f64,
            plain.as_secs_f64() / mont.as_secs_f64(),
        );
        // Parsing bytes is the third suspect, and it has to be
        // measured rather than named. `add_many` receives ciphertexts as
        // a list of `bytes`, each parsed into an `Integer` afresh.
        let raw = a.to_digits::<u8>(rug::integer::Order::MsfBe);
        let started = Instant::now();
        let mut guard = Integer::from(0);
        for _ in 0..ROUNDS {
            guard += Integer::from_digits(&raw, rug::integer::Order::MsfBe)
                .significant_bits();
        }
        let parse = started.elapsed();
        println!(
            "parse {} bytes into Integer  {:8.3?}  {:6.2} us/op",
            raw.len(),
            parse,
            parse.as_secs_f64() * 1e6 / ROUNDS as f64,
        );
        println!(
            "  parse + multiply together   {:6.2} us/op",
            (parse.as_secs_f64() + plain.as_secs_f64()) * 1e6 / ROUNDS as f64,
        );

        // An exact copy of the `add_many` loop: its own bytes per
        // term, parsed and multiplied as in production.
        //
        // This used to print "(measured 85 in add_many)" — a literal
        // from a measurement long gone: 85 µs was before the move to a
        // short exponent, while `benches/measure.py` now gives 6.9. A
        // benchmark written to explain a gap kept printing a gap that no
        // longer exists — and would have printed it forever, because a
        // literal is recomputed from nothing.
        //
        // Compare against a line of this same output, not against a
        // number from memory.
        let blobs: Vec<Vec<u8>> = (0..10_000u32)
            .map(|i| {
                (Integer::from(&nn / 7u32) + i)
                    .to_digits::<u8>(rug::integer::Order::MsfBe)
            })
            .collect();
        let started = Instant::now();
        let mut total = Integer::from(1);
        for blob in &blobs {
            let value = Integer::from_digits(blob, rug::integer::Order::MsfBe);
            total = total * value % &nn;
        }
        let replica = started.elapsed();
        println!(
            "copy of the add_many loop {:8.3?}  {:6.2} us/term",
            replica,
            replica.as_secs_f64() * 1e6 / blobs.len() as f64,
        );

        // So the optimiser does not throw the loops away.
        assert!(acc > 0 && acc_m > 0 && guard > 0 && total > 0);
    }
}
