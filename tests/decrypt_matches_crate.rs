//! Our decryption must give EXACTLY what the reference crate gives.
//!
//! It was rewritten for `secure_pow_mod` instead of `pow_mod` — that is,
//! for constant time in the secret exponent, NOT for a different result.
//! So what has to be checked is equality of results, not a round trip: a
//! round trip stays green on broken decryption if encryption is wrong in
//! the same way.
//!
//! The reference is `fast_paillier::DecryptionKey::decrypt`, an
//! independent implementation of the same algorithm on the same primes.

use fast_paillier::{DecryptionKey, Plaintext};
use paillier::secret::Decryptor;
use rug::Integer;

/// A key smaller than a production one: the algebra does not depend on
/// the size and the test should be fast. The primes are FAR apart, so
/// the fixture cannot be copied as a model key.
fn key() -> (DecryptionKey, Integer, Integer) {
    let mut p = (Integer::from(1) << 256u32) + 1u32;
    p.next_prime_mut();
    let mut q = (Integer::from(1) << 200u32) + 7u32;
    q.next_prime_mut();
    let dk = DecryptionKey::from_primes(
        Plaintext::from_rug(p.clone()),
        Plaintext::from_rug(q.clone()),
    )
    .expect("the key assembles");
    (dk, p, q)
}

fn to_rug(value: &Plaintext) -> Integer {
    value.to_string().parse().expect("decimal notation")
}

#[test]
fn our_decryption_matches_the_reference_crate() {
    let (dk, p, q) = key();
    let ours = Decryptor::new(&p, &q).expect("the decryptor assembles");
    let ek = dk.encryption_key();
    let n = to_rug(ek.n());

    // Values across the whole range, including sign and the edges.
    let mut probes = vec![
        Integer::from(0),
        Integer::from(1),
        Integer::from(-1),
        Integer::from(1234567890u64),
        Integer::from(-987654321i64),
    ];
    probes.push(Integer::from(&n / 2u32) - 1u32);
    probes.push(-(Integer::from(&n / 2u32) - 1u32));

    let mut rng = rand::thread_rng();
    for value in probes {
        let plain = Plaintext::from_rug(value.clone());
        let (cipher, _nonce) = ek
            .encrypt_with_random(&mut rng, &plain)
            .expect("encryption");
        let expected = to_rug(&dk.decrypt(&cipher).expect("the crate decrypts"));

        let raw = cipher.to_bytes_msf();
        let got = ours
            .decrypt(&Integer::from_digits(&raw, rug::integer::Order::MsfBe))
            .expect("our decryptor");

        assert_eq!(got, expected, "value {value}");
        assert_eq!(got, value, "and it is the original number");
    }
}

#[test]
fn an_invalid_ciphertext_is_refused() {
    let (dk, p, q) = key();
    let ours = Decryptor::new(&p, &q).expect("the decryptor");
    let n = to_rug(dk.encryption_key().n());
    let nn = Integer::from(&n * &n);

    // Zero: not invertible, and not a ciphertext of any plaintext.
    assert_eq!(ours.decrypt(&Integer::from(0)), None);
    // Exactly the modulus: outside `[1, n²)`.
    assert_eq!(ours.decrypt(&nn), None);
    // Above the modulus.
    assert_eq!(ours.decrypt(&(nn.clone() + 1u32)), None);
    // Not invertible: `n` divides `n²`, so `gcd(n, n) = n ≠ 1`.
    assert_eq!(ours.decrypt(&n), None);
}

#[test]
fn a_homomorphic_sum_decrypts_with_ours() {
    // Separate from the round trip: a sum is a PRODUCT of ciphertexts,
    // i.e. an input that encryption does not produce directly.
    let (dk, p, q) = key();
    let ours = Decryptor::new(&p, &q).expect("the decryptor");
    let ek = dk.encryption_key();
    let n = to_rug(ek.n());
    let nn = Integer::from(&n * &n);

    let mut rng = rand::thread_rng();
    let mut product = Integer::from(1);
    let mut total = Integer::from(0);
    for value in [10i64, -3, 500, -7] {
        let plain = Plaintext::from_rug(Integer::from(value));
        let (cipher, _nonce) = ek
            .encrypt_with_random(&mut rng, &plain)
            .expect("encryption");
        let raw = cipher.to_bytes_msf();
        product = product * Integer::from_digits(&raw, rug::integer::Order::MsfBe) % &nn;
        total += value;
    }

    assert_eq!(ours.decrypt(&product), Some(total));
}
