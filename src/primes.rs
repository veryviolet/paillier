//! Safe prime generation.
//!
//! # A safe prime
//!
//! `p = 2p′ + 1` with `p′` prime as well. This is where `λ = 2p′q′`
//! comes from — a large prime divisor of the order, which is the
//! security condition for the short exponent
//! (`docs/short-exponent-security.md`). Blumness (`p ≡ 3 mod 4`) comes
//! for free: `p′` is odd, so `2p′ + 1 ≡ 3`.
//!
//! # Why a double sieve rather than "just test them one by one"
//!
//! The density of safe primes is about `2/ln²N`: at 1024 bits that is
//! one candidate in a quarter of a million. Miller–Rabin at 1024 bits
//! costs fractions of a millisecond, and a quarter of a million such
//! tests is minutes per prime.
//!
//! So a candidate is first sieved by division by small primes — BOTH
//! itself AND `2p′+1`. The sieving is cheap and removes over 90 % of
//! candidates before the first exponentiation.

use rand::Rng;
use rug::integer::{IsPrime, Order};
use rug::Integer;

use crate::keys::PRIMALITY_ROUNDS;

/// The sieve bound. Above it, sieving stops paying: the fraction of
/// candidates removed by a prime `s` is `1/s`, while the cost of a
/// division is constant.
const SIEVE_LIMIT: u32 = 1 << 12;

/// Odd primes up to `SIEVE_LIMIT`.
///
/// Two is absent DELIBERATELY: `half` is odd by construction and
/// `2·half + 1` is odd a fortiori, so dividing by two would never
/// reject anything.
///
/// Even candidates, however, used to survive and land in the list as
/// "primes". The outer loop walked every number from three upward, two
/// crossed nothing off at all, and an even number was only crossed off
/// if an odd prime reached it — and those start at `p²`. So 4, 6, 8,
/// 10, 14, 22, 26, 34 and onward survived: **310 composites out of 873
/// entries**, sitting at positions 2, 4, 6, 7, i.e. paid for on nearly
/// every candidate. It caused no wrong rejection (an even number does
/// not divide an odd one), but a third of the sieve's work was futile,
/// and the cost model in this file's docstring — "a prime `s` removes a
/// fraction `1/s`" — does not hold for that third.
fn small_primes() -> Vec<u32> {
    let mut composite = vec![false; (SIEVE_LIMIT + 1) as usize];
    let mut out = Vec::new();
    let mut candidate = 3;
    while candidate <= SIEVE_LIMIT {
        if !composite[candidate as usize] {
            out.push(candidate);
            // Step by `2·candidate`, not `candidate`: even multiples
            // need no marking, they never enter the walk.
            let mut multiple = candidate as u64 * candidate as u64;
            while multiple <= SIEVE_LIMIT as u64 {
                composite[multiple as usize] = true;
                multiple += 2 * candidate as u64;
            }
        }
        candidate += 2;
    }
    out
}

/// A random odd number of exactly `bits` bits.
///
/// The top bit is set EXPLICITLY: without it the length is "about
/// `bits`", and the product of two such primes comes out shorter than
/// the declared modulus — exactly the drift that once made the exponent
/// length be computed from the requested size instead of the actual
/// one.
fn random_odd(bits: u32) -> Integer {
    let mut rng = rand::thread_rng();
    let width = ((bits + 7) / 8) as usize;
    let mut raw = vec![0u8; width];
    rng.fill(&mut raw[..]);
    let mut value = Integer::from_digits(&raw, Order::MsfBe);
    value.keep_bits_mut(bits);
    value.set_bit(bits - 1, true);
    value.set_bit(0, true);
    value
}

/// A safe prime of exactly `bits` bits: `p = 2p′ + 1` with `p′` prime.
///
/// Returns `p`. Costs seconds at 1024 bits; it happens once per key.
pub fn safe_prime(bits: u32) -> Integer {
    assert!(bits >= 8, "a safe prime shorter than eight bits is not searched for");
    let sieve = small_primes();
    loop {
        // Look for `p′` of length `bits − 1`, so that `p = 2p′ + 1` comes
        // out at exactly `bits`.
        let half = random_odd(bits - 1);

        // Sieve on both at once: `p′` and `2p′ + 1`. Testing them in
        // turn would mean paying Miller–Rabin for candidates a division
        // can see through.
        let mut rejected = false;
        for prime in &sieve {
            // The sieve stops once it has grown up to the candidate
            // itself. Without this, every viable candidate was rejected
            // whenever `half < SIEVE_LIMIT`: `half` prime means it
            // coincides with one of the sieving primes, `residue == 0`,
            // rejection. The loop then never terminated — and it runs
            // with the GIL released, i.e. an uninterruptible hang,
            // exactly what the length bounds on keys exist for.
            //
            // Unreachable on the production path (`half ≥ 2^1023`), but
            // the function is public and its contract is stated by the
            // assertion above.
            if Integer::from(*prime) >= half {
                break;
            }
            let residue = half.mod_u(*prime);
            // `p′ ≡ 0` — composite; `2p′ + 1 ≡ 0` — the second one is.
            if residue == 0 || (2 * residue + 1) % prime == 0 {
                rejected = true;
                break;
            }
        }
        if rejected {
            continue;
        }

        if half.is_probably_prime(PRIMALITY_ROUNDS) == IsPrime::No {
            continue;
        }
        let candidate = Integer::from(&half * 2u32) + 1u32;
        if candidate.is_probably_prime(PRIMALITY_ROUNDS) != IsPrime::No {
            debug_assert_eq!(candidate.significant_bits(), bits);
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trial division — an independent judge, not the same sieve.
    fn is_prime_by_division(value: u32) -> bool {
        if value < 2 {
            return false;
        }
        let mut divisor = 2u32;
        while divisor * divisor <= value {
            if value % divisor == 0 {
                return false;
            }
            divisor += 1;
        }
        true
    }

    /// The sieve must return EXACTLY the odd primes: no composite, none
    /// missing.
    ///
    /// The first assertion matters more than the second. Composites in
    /// the list caused no wrong rejection — an even number does not
    /// divide an odd one — so no prime-generation test ever saw them:
    /// `safe_prime` returned correct numbers while wasting a third of
    /// the work. A claim about the list has to be checked on the list.
    #[test]
    fn sieve_returns_exactly_the_odd_primes() {
        let sieve = small_primes();
        for value in &sieve {
            assert!(
                is_prime_by_division(*value),
                "composite {value} in the list"
            );
            assert!(value % 2 == 1, "even {value} in the list");
        }
        let mut expected = Vec::new();
        let mut value = 3u32;
        while value <= SIEVE_LIMIT {
            if is_prime_by_division(value) {
                expected.push(value);
            }
            value += 2;
        }
        assert_eq!(sieve, expected, "sieve and trial division disagree");
    }
}
