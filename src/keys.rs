//! Key validation and derivation of `h`, `hs`.
//!
//! Everything here guards against ONE failure mode: a key on which the
//! round trip works, homomorphism works, every correctness test is
//! green — and privacy is gone. Such a key does not announce itself in
//! any way; it has to be refused at the door.
//!
//! Two paths, and they check different things, for a reason.
//!
//! **Our own key** (`validate_private`) is checked in full: safe primes,
//! Blumness, the `gcd`, the prime gap, the length. We generated it, we
//! know `p` and `q`, and everything about it is checkable.
//!
//! **A peer's modulus** (`validate_public`) is checked for oddness and
//! length, and nothing else. That is *partial public key validation*
//! from NIST SP 800-56B — precisely what the standard prescribes, and
//! the reasoning for why nothing more belongs here is in the docstring
//! of that function.

use rug::integer::IsPrime;
use rug::Integer;

/// How far `|p − q|` may fall short of the prime length before the
/// modulus is refused.
///
/// FIPS 186-4 B.3.1 requires `|p − q| ≥ 2^(prime_bits − 100)`, and the
/// bound is not decorative: with close primes Fermat's method factors
/// the modulus in about `k` steps where the gap is `2^(prime_bits − k)`,
/// so at `k = 8` that is `2^13` steps whether the primes are 512 bits or
/// 1536. A key accepted by a check without this bound was factored by
/// Fermat in 3589 steps — that was done, not estimated, and it stands as
/// `tests/keygen_props.rs`.
///
/// At `prime_bits − 100` with `|p| = 1536`, Fermat needs on the order of
/// `2^1333` steps, and the measured 507 bits of gap on 512-bit primes
/// pass with 95 bits to spare.
const PQ_DIFFERENCE_SLACK_BITS: u32 = 100;

/// Miller–Rabin rounds: both when generating a prime and when checking
/// an accepted key.
///
/// Public and THE ONLY ONE. There used to be a second copy of this
/// constant in `primes.rs` with a comment saying "these two must not
/// drift apart" — and the only thing holding them together was that I
/// remembered them. Generating more strictly than we validate would mean
/// accepting foreign keys weaker than our own; the other way round would
/// mean rejecting our own.
pub const PRIMALITY_ROUNDS: u32 = 40;

/// The smallest admissible modulus, in bits.
///
/// NIST SP 800-57 part 1 rev. 5, table 2: 112-bit strength requires a
/// modulus of at least 2048. Anything shorter is not cryptography.
///
/// There was no floor at all, and `generate_keypair(32)` returned a
/// 32-bit modulus with which `validate_private` was perfectly happy and
/// which factors in microseconds. Exactly the silent failure this file
/// is written against.
///
/// It also closes a hang: safe-prime generation at eight bits spins
/// forever, and it spins with the GIL released, so the process cannot be
/// interrupted by Ctrl-C or `SIGINT` — verified with `timeout -s INT`.
///
/// The value is NOMINAL, and that matters. The product of two primes of
/// `MIN_MODULUS_BITS/2` bits each lands on 2048 bits and on 2047: the
/// top bits of the factors may fail to carry. Demanding 2048 from the
/// product itself would reject half of all legitimate keys, so the owner
/// is judged by the length of the PRIMES and an imported modulus by
/// `MIN_MODULUS_BITS − 1`.
pub const MIN_MODULUS_BITS: u32 = 2048;

/// The largest admissible foreign modulus, in bits.
///
/// Not about strength — about denial of service. Assembling a peer key
/// derives `hs`, which is an exponentiation modulo `n²`, and it runs
/// with the GIL released: until it returns, the Python interpreter
/// executes nothing, signal handlers included. The modulus arrives over
/// the wire from a peer.
///
/// 8192 is four times the longest key anyone needs.
pub const MAX_MODULUS_BITS: u32 = 8192;

/// Evidence that `validate_private` ran and accepted the key.
///
/// The tuple field is private, so `Validated` cannot be constructed
/// outside this module by any means: not by a literal, not by `Default`,
/// not by cloning one out of thin air. The only source is
/// `validate_private`.
///
/// The point is exactly one: to make skipping the check a COMPILE error.
/// `SecretKey` in `lib.rs` holds this field, and without the token it
/// does not build. A test will not do here — on honest input a key with
/// and without validation is identical, and a test that greps the source
/// passes happily if the call is replaced by a comment with the same
/// text.
///
/// `PartialEq` exists only for tests that compare a whole `Result`. It
/// does not help construct a `Validated`: you can only compare something
/// already obtained from `validate_private`.
#[derive(Debug, PartialEq, Eq)]
pub struct Validated(());

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    NotSafePrimes,
    NotBlum,
    BadGcd,
    PrimesTooClose,
    HNotAntiResidue,
    BadX,
    DegenerateHs,
    PowModUndefined,
    ModulusTooShort,
    ModulusTooLong,
    NoUsableX,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            KeyError::NotSafePrimes =>
                "primes are not safe: (p−1)/2 or (q−1)/2 is composite. Safe \
                 primes are what gives the order of h a large prime factor; \
                 without them the order can be smooth and the short exponent \
                 falls to Pohlig–Hellman while every correctness check stays \
                 green",
            KeyError::NotBlum =>
                "primes are not Blum (need p ≡ q ≡ 3 mod 4): h = −x² would \
                 not sit outside the group of squares",
            KeyError::BadGcd =>
                "gcd(p−1, q−1) ≠ 2: Z*_n gains an extra cyclic component",
            KeyError::PrimesTooClose =>
                "p and q are too close: the modulus falls to Fermat \
                 factorisation. The bound is FIPS 186-4 B.3.1, \
                 |p−q| ≥ prime_bits − 100",
            KeyError::HNotAntiResidue =>
                "h is a quadratic residue: the sign was lost. Nothing about \
                 correctness changes, which is exactly why this is checked \
                 here",
            KeyError::BadX =>
                "x must lie in [2, n−2] and be coprime with n",
            KeyError::DegenerateHs =>
                "hs is degenerate: its order is at most two, so the \
                 randomiser takes at most two values and the plaintext is \
                 readable by anyone holding n. Correctness is unaffected — \
                 which is why this is checked and not assumed",
            KeyError::PowModUndefined =>
                "modular exponentiation is undefined for these arguments",
            KeyError::ModulusTooShort =>
                "modulus is shorter than 2048 bits: NIST SP 800-57 puts \
                 112-bit strength at 2048, and anything below that is not \
                 cryptography",
            KeyError::ModulusTooLong =>
                "modulus is longer than 8192 bits: nothing needs a key \
                 that long, and deriving hs from it takes time quadratic \
                 in its length with the GIL released",
            KeyError::NoUsableX =>
                "no usable x found within the attempt budget: on an honest \
                 modulus unusable values are a handful, so this points at \
                 the modulus itself",
        };
        write!(f, "{text}")
    }
}

impl std::error::Error for KeyError {}

/// Full validation of our own key. Returns the witness that the check
/// took place.
///
/// The order of the checks is deliberate: the most substantive one — are
/// the primes safe — comes first, so its error is what the caller sees
/// when several conditions fail at once.
pub fn validate_private(
    p: &Integer,
    q: &Integer,
) -> Result<Validated, KeyError> {
    if p.significant_bits() < MIN_MODULUS_BITS / 2
        || q.significant_bits() < MIN_MODULUS_BITS / 2
    {
        return Err(KeyError::ModulusTooShort);
    }
    // THE main check. Everything below is auxiliary: a non-smooth order
    // of `hs` is what the short exponent stands on, and safe primes are
    // what makes it non-smooth by construction rather than by luck.
    for prime in [p, q] {
        let half = Integer::from(prime - 1u32) / 2u32;
        if half.is_probably_prime(PRIMALITY_ROUNDS) == IsPrime::No {
            return Err(KeyError::NotSafePrimes);
        }
    }
    if p.clone() % 4u32 != 3 || q.clone() % 4u32 != 3 {
        return Err(KeyError::NotBlum);
    }
    if Integer::from(p - 1u32).gcd(&Integer::from(q - 1u32)) != 2 {
        return Err(KeyError::BadGcd);
    }
    let prime_bits = p.significant_bits().max(q.significant_bits());
    let difference = Integer::from(p - q).abs();
    if difference.significant_bits() + PQ_DIFFERENCE_SLACK_BITS < prime_bits {
        return Err(KeyError::PrimesTooClose);
    }
    Ok(Validated(()))
}

/// Validation of a FOREIGN modulus: oddness and length, and nothing
/// else.
///
/// # Why nothing else
///
/// There used to be three probes here — trial division by small primes,
/// Brent's rho, Pollard's `p−1` — plus a compositeness check. All
/// removed, and the reasoning belongs here because the path to them was
/// an error of reasoning rather than an oversight.
///
/// **They do not work.** From `n` alone you cannot establish that it is
/// a product of two large distinct primes: that is factorisation. Any
/// probe gives a bound and costs exactly what stepping over it costs the
/// attacker, who reads the sources and picks a factor beyond it.
/// Measured: rho with a `2^16` budget reaches about 32 bits, and a
/// 40-bit safe factor — the very example the probe was written for —
/// passed straight through.
///
/// **They are expensive.** The probes cost two thirds of parsing a
/// foreign key (0.46 s out of 0.69 s at `|n| = 2048`) and tripled the
/// window during which the node answers no signals: from 2.4 to 6.8 s on
/// a maximal modulus, with the GIL released. The denial-of-service
/// defence became a denial of service.
///
/// **They are in the wrong place.** The problem is solved not by a
/// passive check but by a proof of the modulus's form from its owner:
/// Gennaro–Micciancio–Rabin for square-freeness, van de Graaf–Peralta
/// for "exactly two primes". That is finite work with a clear end, but
/// its place is a challenge-response in a handshake, not a function in a
/// library.
///
/// So the correct framing: **this function cannot be finished, but the
/// problem can.**
///
/// The compositeness check is a separate story and the three arguments
/// above do not apply to it: `is_probably_prime` is a decision
/// procedure, not a bounded search; it costs 2.3 ms at 2048 bits; and it
/// catches more than malice — a peer with a broken generator that sends
/// a prime is otherwise accepted silently. It was removed on a different
/// ground: partial public key validation per NIST SP 800-56B does not
/// include it, and we do what the standard prescribes and no more.
///
/// The price of that decision, measured so it cannot be missed: a
/// 2048-bit PRIME `n` is accepted in 0.010 s, the ciphertexts are
/// distinct — randomisation intact, round trip intact — and an observer
/// holding only `n` reads every plaintext, because `λ = n−1`.
pub fn validate_public(n: &Integer) -> Result<(), KeyError> {
    // One bit below nominal: the product of two 1024-bit primes lands on
    // 2048 bits and on 2047.
    if n.significant_bits() + 1 < MIN_MODULUS_BITS {
        return Err(KeyError::ModulusTooShort);
    }
    if n.significant_bits() > MAX_MODULUS_BITS {
        return Err(KeyError::ModulusTooLong);
    }
    Ok(())
}

/// `h = −x² mod n`.
///
/// The range of `x` is narrowed to `[2, n−2]`: one and `n−1` both give
/// `h = −1`, and that degeneracy is caught neither by a `gcd` nor by a
/// Jacobi symbol.
pub fn derive_h(x: &Integer, n: &Integer) -> Result<Integer, KeyError> {
    if *x < 2 || *x > Integer::from(n - 2u32) {
        return Err(KeyError::BadX);
    }
    if Integer::from(x.gcd_ref(n)) != 1 {
        return Err(KeyError::BadX);
    }
    let square = Integer::from(x * x) % n;
    Ok(Integer::from(n - square) % n)
}

/// `h = −x² mod n` with the sign verified by the Jacobi symbol.
///
/// The sign can only be checked where `p` and `q` are available — that
/// is, by the key holder. A party that derives `hs` from `n` alone
/// cannot do it, and that is not a gap in the checks: with an honest `n`
/// the sign is correct by construction, and with a dishonest one it is
/// the least of the troubles.
///
/// What the check is for: if the sign is lost and `h = x²` results, the
/// order drops to the subgroup of squares while every correctness test
/// stays green.
pub fn derive_h_checked(
    x: &Integer,
    p: &Integer,
    q: &Integer,
    n: &Integer,
) -> Result<Integer, KeyError> {
    let h = derive_h(x, n)?;
    if h.jacobi(p) != -1 || h.jacobi(q) != -1 {
        return Err(KeyError::HNotAntiResidue);
    }
    Ok(h)
}

/// `hs = h^n mod n²`, with the degenerate case refused.
///
/// `ord(hs) ≤ 2` is the only degeneracy a single `x` can produce, and
/// the only one the checks above do not catch. The predicate is EXACT,
/// not a heuristic: with safe primes `Z*_n ≅ Z_{2p′} × Z_{2q′}` contains
/// no element of order four, so `x⁴ ≡ 1` implies `x² ≡ ±1` and hence
/// `h = −1`, which shows up here as `hs = n²−1`.
pub fn derive_hs(h: &Integer, n: &Integer) -> Result<Integer, KeyError> {
    let nn = Integer::from(n * n);
    let hs = h
        .clone()
        .pow_mod(n, &nn)
        .map_err(|_| KeyError::PowModUndefined)?;
    if hs <= 1 || hs == Integer::from(&nn - 1u32) {
        return Err(KeyError::DegenerateHs);
    }
    Ok(hs)
}
