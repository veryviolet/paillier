//! Decryption: Chinese Remainder Theorem plus exponent-secure powering.
//!
//! # Why our own, when the crate has one
//!
//! `fast-paillier` decrypts through `rug::Integer::pow_mod`, i.e.
//! through GMP's `mpz_powm`. The exponent there derives from `λ` — from
//! the LONG-LIVED secret of the key.
//!
//! GMP's own documentation says it plainly for `mpz_powm`: secret
//! exponents need `mpz_powm_sec`. The difference is that `mpz_powm` is a
//! windowed exponentiation indexing a table by the exponent's bits,
//! while `mpz_powm_sec` reads the whole table at every step.
//!
//! The scale of that difference is worth naming. Everything fixed in
//! encryption concerned the channel around a one-shot `r`, at a cost of
//! fractions of a bit per message. Here the channel is around `λ`
//! itself: one value for the whole life of the key, with the leak
//! accumulating across every decryption rather than starting afresh each
//! time.
//!
//! # What this function does
//!
//! 1. ciphertext check: `c` must lie in `Z*_{n²}`;
//! 2. `c^(p−1) mod p²` and `c^(q−1) mod q²` — TWO exponentiations with
//!    short exponents instead of one long one modulo `n²`;
//! 3. the `L` function in each component, multiplied by a prepared
//!    inverse;
//! 4. recombination by the CRT;
//! 5. signed representative: `m > n/2` means negative.
//!
//! The CRT here is not decoration: without it the exponent is twice as
//! long and the modulus twice as wide, i.e. four times the cost.

use rug::ops::RemRounding;
use rug::Integer;

/// Everything prepared for decryption. Computed ONCE when the key is
/// assembled.
///
/// Everything here derives from `p` and `q` and is secret.
pub struct Decryptor {
    n: Integer,
    /// `n²` — prepared, not recomputed on every call.
    n_square: Integer,
    n_half: Integer,
    p: Integer,
    q: Integer,
    p_square: Integer,
    q_square: Integer,
    /// `p − 1` and `q − 1` — the component exponents.
    p_minus_1: Integer,
    q_minus_1: Integer,
    /// `(L_p(g^(p−1) mod p²))^{-1} mod p`, and the same for `q`.
    hp: Integer,
    hq: Integer,
    /// `p^{-1} mod q` — for the recombination.
    p_inverse_mod_q: Integer,
}

/// `L(x) = (x − 1) / divisor`, exact division.
///
/// Exact rather than with a remainder: `x ≡ 1 (mod divisor)` holds by
/// construction, and if it suddenly does not, the input is not a
/// ciphertext. A remainder here would be silently discarded.
fn l_function(value: &Integer, divisor: &Integer) -> Option<Integer> {
    let shifted = Integer::from(value - 1u32);
    let (quotient, remainder) = shifted.div_rem(divisor.clone());
    if remainder == 0 {
        Some(quotient)
    } else {
        None
    }
}

impl Decryptor {
    pub fn new(p: &Integer, q: &Integer) -> Option<Self> {
        let n = Integer::from(p * q);
        let n_square = Integer::from(&n * &n);
        let p_square = Integer::from(p * p);
        let q_square = Integer::from(q * q);
        let p_minus_1 = Integer::from(p - 1u32);
        let q_minus_1 = Integer::from(q - 1u32);

        // With `g = n + 1`, `g^(p−1) mod p² = 1 + (p−1)·n mod p²`.
        // Computed directly, with no exponentiation.
        let gp = (Integer::from(&p_minus_1 * &n) + 1u32) % &p_square;
        let gq = (Integer::from(&q_minus_1 * &n) + 1u32) % &q_square;
        let hp = l_function(&gp, p)?.invert(p).ok()?;
        let hq = l_function(&gq, q)?.invert(q).ok()?;

        let p_inverse_mod_q = p.clone().invert(q).ok()?;
        let n_half = Integer::from(&n >> 1u32);

        Some(Self {
            n,
            n_square,
            n_half,
            p: p.clone(),
            q: q.clone(),
            p_square,
            q_square,
            p_minus_1,
            q_minus_1,
            hp,
            hq,
            p_inverse_mod_q,
        })
    }

    /// The plaintext as a SIGNED integer, or `None` on bad input.
    ///
    /// `secure_pow_mod` instead of `pow_mod` is the only substantive
    /// difference from the crate's implementation, and it is the reason
    /// all of this was rewritten.
    ///
    /// # There is NO guard on this line, and that is acknowledged, not
    /// forgotten
    ///
    /// There is nothing to check a substitution with. Both functions
    /// return the same result. Their timing spread across calls is the
    /// same too: the exponent is fixed for a key, so both are
    /// deterministic, and the leak goes through the cache rather than
    /// through wall-clock time.
    ///
    /// What is left is the difference in speed, and I tried to guard
    /// with that. Measured: healthy code gives a ratio of 1.68 against
    /// the insecure path, the substituted one 1.40, with machine noise
    /// around 15 %. A threshold between them would have 12 % of margin
    /// — that is a flaky test, and a flaky test is worse than none: it
    /// teaches you to disbelieve red. The test was written and deleted.
    ///
    /// The cost of the property is measured separately and without
    /// substitutions — `benches/secure_pow.rs`: at the lengths of the
    /// CRT components, `powm_sec` is 1.54× dearer than `powm` at
    /// `|n| = 2048` and 1.67× at 3072.
    ///
    /// So only reading the code works here. It is one line, and it is in
    /// front of you.
    pub fn decrypt(&self, cipher: &Integer) -> Option<Integer> {
        if *cipher < 1 || *cipher >= self.n_square {
            return None;
        }
        // A ciphertext must be invertible: otherwise it is not the image
        // of encrypting anything. The crate checks the same
        // (`in_mult_group_of`), and the check is not redundant here —
        // `add_many` does not do it, because there it would cost more
        // than the operation.
        if Integer::from(cipher.gcd_ref(&self.n)) != 1 {
            return None;
        }

        let mp = cipher
            .clone()
            .secure_pow_mod(&self.p_minus_1, &self.p_square);
        let mp = l_function(&mp, &self.p)? * &self.hp % &self.p;

        let mq = cipher
            .clone()
            .secure_pow_mod(&self.q_minus_1, &self.q_square);
        let mq = l_function(&mq, &self.q)? * &self.hq % &self.q;

        // Recombination: `m = mp + p · ((mq − mp) · p^{-1} mod q)`.
        let difference = (Integer::from(&mq - &mp) * &self.p_inverse_mod_q)
            .rem_euc(self.q.clone());
        let plain = mp + Integer::from(&self.p * &difference);

        // Signed representative. The encoding uses the whole range
        // `(−n/2, n/2)`, and without this step negative values would
        // come back as enormous positive ones.
        if plain > self.n_half {
            Some(plain - &self.n)
        } else {
            Some(plain)
        }
    }
}
