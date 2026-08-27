//! Our generator must produce SAFE primes specifically.
//!
//! What is checked is not "looks prime" but exactly the properties that
//! short-exponent security rests on and that `keys::validate_private`
//! requires:
//!
//! - `p` is prime;
//! - `(p−1)/2` is prime — hence `λ = 2p′q′` with a large prime factor;
//! - the length is EXACTLY the one asked for, not "about".
//!
//! The last is not pedantry: because of "about", the product of two
//! primes came out shorter than the declared modulus, and the exponent
//! length drifted apart between the owner and the peer.

use paillier::keys::validate_private;
use paillier::primes::safe_prime;
use rug::integer::IsPrime;
use rug::Integer;

/// The size to run at. Small — the properties do not depend on the size,
/// and finding a 1024-bit safe prime takes seconds.
const BITS: u32 = 128;

#[test]
fn yields_safe_primes_of_the_requested_length() {
    for _ in 0..8 {
        let p = safe_prime(BITS);

        assert_eq!(p.significant_bits(), BITS, "the length is exactly as asked");
        assert_ne!(
            p.is_probably_prime(40),
            IsPrime::No,
            "p itself must be prime",
        );
        let half = Integer::from(&p - 1u32) / 2u32;
        assert_ne!(
            half.is_probably_prime(40),
            IsPrime::No,
            "(p-1)/2 must be prime — otherwise the prime is not safe",
        );
        assert_eq!(p.clone() % 4u32, 3, "Blum-ness comes for free");
    }
}

#[test]
fn two_in_a_row_differ() {
    // Catches a generator that returned a constant or failed to stir its
    // seed.
    let first = safe_prime(BITS);
    let second = safe_prime(BITS);

    assert_ne!(first, second);
}

#[test]
fn a_key_from_our_primes_passes_validation() {
    // End to end: what the generator produces must pass
    // `validate_private` — otherwise one half of the code argues with the
    // other.
    let p = safe_prime(1024);
    let q = safe_prime(1024);

    assert!(
        validate_private(&p, &q).is_ok(),
        "our generator must produce what our own check accepts",
    );
}

#[test]
fn returns_at_small_sizes() {
    // The sieve ran over primes up to 4096 and refused EVERY valid
    // candidate while `half` was itself below that bound: a prime `half`
    // coincided with one of the sieving primes. The loop never ended —
    // and with the GIL released that is an uninterruptible hang, the same
    // class of failure the length bounds on the key exist for.
    //
    // The production path is untouched (`half >= 2^1023`), but the
    // function's contract is declared by the assertion `bits >= 8`, and it
    // has to hold.
    for bits in [8u32, 9, 10, 12, 13, 14, 16] {
        let p = safe_prime(bits);
        assert_eq!(p.significant_bits(), bits, "size {bits}");
        let half = Integer::from(&p - 1u32) / 2u32;
        assert_ne!(half.is_probably_prime(40), IsPrime::No, "size {bits}");
    }
}
