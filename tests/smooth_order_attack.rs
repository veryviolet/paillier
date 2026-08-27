//! Why safe primes are the PRINCIPAL check on OUR key.
//!
//! What is shown here is not that `validate_private` returns the right
//! error variant. It is WHAT HAPPENS to a key that this check refuses:
//! the modulus factors and the plaintext comes out whole — even though
//! the key is Blum, `gcd(p−1, q−1) = 2`, and the primes are far apart.
//!
//! The first version of this file proved a different claim than the one
//! it stated, and that is worth recording. It recovered the exponent `r`
//! by Pohlig–Hellman and called that an attack on the short exponent —
//! but it carried two quantities across the line "from here on, only `n`
//! and the ciphertext" that an observer does not have: `hs` itself (the
//! encrypting side derives it from a random `x` and never publishes it)
//! and the order of `hs` (computed from `λ`, i.e. from `p` and `q`).
//!
//! Worse, such a key breaks with no connection to the short exponent at
//! all: with smooth `p−1`, Pollard's `p−1` works, and that is a method
//! against the MODULUS, not against the randomiser. So the counterexample
//! showed "smooth `p−1` ruins any Paillier" — a true and important claim,
//! but a different one.
//!
//! So that is exactly what is proved here, honestly: the attack uses
//! ONLY `n`. The requirement that the order of `hs` be non-smooth, which
//! is specific to the short exponent, is guarded by `DegenerateHs` — see
//! `tests/degenerate_x.rs`.
//!
//! What is NO LONGER here: tests for probing a peer's modulus. There are
//! no probes left — `validate_public` checks the length and nothing else,
//! as *partial public key validation* should. Why there should be no
//! probes is set out in its docstring.

use paillier::keys::{
    derive_h, derive_hs, validate_private, validate_public, KeyError,
    MIN_MODULUS_BITS,
};
use rand::seq::SliceRandom;
use rand::Rng;
use rug::integer::{IsPrime, Order};
use rug::ops::RemRounding;
use rug::Integer;

/// Primes for assembling a smooth `p−1`. Different pools for `p` and `q`
/// so that `gcd(p−1, q−1) = 2` — otherwise the refusal would come down a
/// different branch and the test would prove the wrong thing.
fn small_primes(from: u32, to: u32) -> Vec<u32> {
    (from..to)
        .filter(|c| Integer::from(*c).is_probably_prime(30) != IsPrime::No)
        .collect()
}

/// A Blum prime `p = 2·s + 1`, where `s` is a product of distinct small
/// primes from `pool`. Every divisor of `p−1` is below the top of the
/// pool, so `p−1` is smooth.
fn smooth_blum_prime(pool: &[u32], target_bits: u32) -> (Integer, Vec<u32>) {
    let mut rng = rand::thread_rng();
    loop {
        let mut chosen: Vec<u32> = Vec::new();
        let mut s = Integer::from(1);
        let mut shuffled = pool.to_vec();
        shuffled.shuffle(&mut rng);
        for prime in shuffled {
            if s.significant_bits() >= target_bits {
                break;
            }
            chosen.push(prime);
            s *= prime;
        }
        let candidate = Integer::from(&s * 2u32) + 1u32;
        if candidate.is_probably_prime(40) != IsPrime::No {
            // `s` is a product of odd primes, hence odd, hence
            // `p = 2s+1 ≡ 3 (mod 4)`. Blum-ness holds.
            assert_eq!(candidate.clone() % 4u32, 3);
            chosen.sort_unstable();
            return (candidate, chosen);
        }
    }
}

/// Pollard's `p−1`: `a^M mod n` with `M = lcm(1..bound)`.
///
/// The only input is `n`. Not `p`, not `q`, not `λ`, not `hs`.
fn pollard_p_minus_1(n: &Integer, bound: u32) -> Option<Integer> {
    let mut base = Integer::from(2);
    for k in 2..=bound {
        base = base.pow_mod(&Integer::from(k), n).ok()?;
        if k % 512 == 0 {
            let divisor = Integer::from(&base - 1u32).gcd(n);
            if divisor > 1 && divisor < *n {
                return Some(divisor);
            }
        }
    }
    let divisor = Integer::from(&base - 1u32).gcd(n);
    if divisor > 1 && divisor < *n {
        Some(divisor)
    } else {
        None
    }
}

#[test]
fn the_length_floor_applies_to_the_owner_too() {
    // `validate_private` is public and is advertised as a key check, yet
    // its length floor held only because `generate_keypair` checks
    // earlier. 23 and 59 are genuine safe primes (11 and 29 are prime),
    // Blum, `gcd(22, 58) = 2`: everything else here is in order, and it
    // is the length that refuses.
    let p = Integer::from(23);
    let q = Integer::from(59);

    assert_eq!(validate_private(&p, &q), Err(KeyError::ModulusTooShort));
}

#[test]
fn a_short_modulus_is_refused_on_import() {
    let n = (Integer::from(1) << 2000u32) + 1u32;

    assert_eq!(validate_public(&n), Err(KeyError::ModulusTooShort));
}

#[test]
fn an_over_long_modulus_is_refused() {
    let n = (Integer::from(1) << 9000u32) + 1u32;

    assert_eq!(validate_public(&n), Err(KeyError::ModulusTooLong));
}

#[test]
fn a_modulus_of_normal_length_is_accepted() {
    // The other side of the bounds: without this, "fixing" them by
    // refusing everything would leave both tests above green.
    let n = (Integer::from(1) << 3071u32) + 1u32;

    assert_eq!(validate_public(&n), Ok(()));
}

#[test]
fn a_key_with_smooth_lambda_gives_up_the_plaintext() {
    // The pools do not overlap — then gcd(p−1, q−1) = 2 and the refusal
    // comes from the safety of the primes rather than from the gcd.
    let (p, factors_p) = smooth_blum_prime(&small_primes(3, 30_000), 1030);
    let (q, factors_q) = smooth_blum_prime(&small_primes(30_000, 65_000), 1050);
    assert!(
        factors_p.iter().all(|f| !factors_q.contains(f)),
        "the factor pools must not overlap",
    );

    let n = Integer::from(&p * &q);
    let nn = Integer::from(&n * &n);
    println!(
        "|p| = {}, |q| = {}, |n| = {}",
        p.significant_bits(),
        q.significant_bits(),
        n.significant_bits(),
    );

    // 1. The key is longer than the floor, Blum, the gcd is right, the
    //    primes are far apart — and it is still refused, because they are
    //    not safe.
    assert!(
        n.significant_bits() >= MIN_MODULUS_BITS,
        "the length must not be the reason",
    );
    assert_eq!(p.clone() % 4u32, 3);
    assert_eq!(q.clone() % 4u32, 3);
    assert_eq!(Integer::from(&p - 1u32).gcd(&Integer::from(&q - 1u32)), 2);
    let difference = Integer::from(&p - &q).abs();
    assert!(
        difference.significant_bits() + 100
            >= p.significant_bits().max(q.significant_bits()),
        "the primes must not be close — otherwise the refusal would come \
         from the Fermat check",
    );
    assert_eq!(
        validate_private(&p, &q),
        Err(KeyError::NotSafePrimes),
        "a key with smooth λ must be refused",
    );

    // 2. Now — what would happen if it were not refused. The ciphertext
    //    is built by OUR code.
    let x = Integer::from(&n / 3u32) + 12345u32;
    let h = derive_h(&x, &n).expect("h");
    let hs = derive_hs(&h, &n).expect("hs");
    let exponent_bits = n.significant_bits() / 2;
    let mut raw = vec![0u8; ((exponent_bits + 7) / 8) as usize];
    rand::thread_rng().fill(&mut raw[..]);
    let r = Integer::from_digits(&raw, Order::MsfBe);
    let secret = Integer::from(4_242_424_242u64);
    let cipher = (Integer::from(1 + secret.clone() * &n)
        * hs.clone().pow_mod(&r, &nn).unwrap())
        % nn.clone();

    // --- from here on, ONLY `n` and the ciphertext are used ---
    let started = std::time::Instant::now();
    let factor = pollard_p_minus_1(&n, 70_000).expect("Pollard must succeed");
    let other = Integer::from(&n / &factor);
    println!(
        "Pollard p−1 factored n in {:?}: divisor of {} bits",
        started.elapsed(),
        factor.significant_bits(),
    );
    assert_eq!(Integer::from(&factor * &other), n, "the divisor is genuine");

    // Holding `p` and `q`, the observer decrypts as the key owner would.
    let lambda = Integer::from(&factor - 1u32).lcm(&Integer::from(&other - 1u32));
    let numerator = cipher.clone().pow_mod(&lambda, &nn).unwrap();
    let l_value = Integer::from(&numerator - 1u32) / &n;
    let mu = Integer::from(&lambda % &n).invert(&n).expect("gcd(λ, n) = 1");
    let plain = (l_value * mu).rem_euc(n.clone());
    println!("plaintext recovered in {:?}", started.elapsed());

    assert_eq!(
        plain, secret,
        "the plaintext must come out — that is the point of the refusal above",
    );
}
