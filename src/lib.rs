//! Paillier: our own implementation on GMP, bound to Python via pyo3.
//!
//! The cryptography is HERE, not in a dependency: safe-prime generation,
//! short-exponent encryption, homomorphic addition, CRT decryption.
//! `fast-paillier` remains ONLY as a reference in tests
//! (`dev-dependencies`) — an implementation checked against itself
//! proves nothing.
//!
//! A blob is a scale byte followed by the ciphertext, most significant
//! byte first. Entries are MINIMAL, not padded to a fixed width:
//! measured `{512: 2, 513: 398}` over four hundred encryptions with a
//! 2048-bit key. You cannot slice the buffer at a constant stride.
//!
//! That number has lied twice. First it said `[255, 256]` — the lengths
//! at a 1024-bit key, which is below `MIN_MODULUS_BITS` and can no
//! longer be generated. Then `[511, 512]` — correct, but from before the
//! scale byte, i.e. the docstring describing the format did not know
//! about the only thing that changed the format.
//!
//! The `rug` backend was not chosen by taste: the crate's default
//! `num-bigint` backend pulls in `glass_pumpkin`, which pulls in
//! `core2`, **all** versions of which were yanked by its author. With
//! `backend-rug` that chain does not exist, and it computes on GMP.
//!
//! Encryption uses a SHORT EXPONENT: instead of `r^n` with a random
//! base, `hs^r` with a fixed one. What that adds to the security
//! assumptions is in `docs/short-exponent-security.md`.

// The one door through which the `keys::Validated` witness could still
// be forged is `unsafe`: `mem::zeroed` builds a zero-sized type out of
// nothing. It stays shut everywhere except one module.
//
// This was `forbid` until Montgomery arithmetic moved down onto limbs.
// `forbid` cannot be lifted per module — that is precisely its purpose
// — so it is now `deny`, which the compiler enforces just as strictly
// but which `src/mont.rs` opts out of for itself, in the open. The
// difference between the two is one `#[allow]` that has to be written
// down and reviewed; it is not a difference in how much is checked.
//
// The exemption cannot reach the witness: `mont` deals in limb buffers
// and does not import `keys`. Everything `unsafe` in this crate is the
// four GMP calls listed at the top of that file.
#![deny(unsafe_code)]

pub mod fast;
pub mod mont;
pub mod primes;
pub mod secret;
pub mod keys;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::Rng;
use rayon::prelude::*;
use rug::integer::Order;
use rug::ops::RemRounding;
use rug::Integer;

use fast::{build_window_table, pow_by_table, windows_for, windows_of};

/// The default scale: `10^8`.
///
/// Deliberately left as it was. It gives the WIDEST input range (up to
/// `|v| ≈ 9e7`), and narrowing the range for accuracy is a decision for
/// the caller who knows their data, not a default of the library.
const DEFAULT_SCALE_POW10: u8 = 8;

/// The largest accepted scale exponent.
///
/// Above `10^18` there is nothing left to encode: `2^53/10^18` is below
/// `1e-2`, so only numbers smaller than a hundredth encode exactly and
/// the error is relative across the whole meaningful input.
const MAX_SCALE_POW10: u8 = 18;

/// The encoding scale: a POWER OF TEN, carried in the ciphertext as its
/// first byte.
///
/// # Why a property of the ciphertext rather than a setting
///
/// A scale mismatch produces not a refusal but a plausible wrong number:
/// encrypt at `1e8`, decrypt at `1e12` and the result is ten thousand
/// times smaller, finite, with no sign of anything wrong. Add
/// ciphertexts of different scales and the sum is meaningless, with
/// nothing to tell them apart: ciphertexts are indistinguishable.
///
/// Worse, a party that only encrypts builds a peer key from `n` alone
/// (`PublicKey::from_n`), and `n` carries no scale — so with a setting
/// "on the side" it would take the default and silently disagree with
/// the key holder.
///
/// Hence `decrypt` reads the scale FROM THE BLOB ITSELF, and `add_many`
/// refuses a batch that mixes scales. There is physically nothing to
/// disagree about.
///
/// The cost is one byte per ciphertext, 0.2 % of its length.
///
/// # Rounding is to nearest
///
/// Not truncation. Truncation toward zero biases every term downward in
/// magnitude, and on SIGN-CONSTANT data the sum's error then grows
/// LINEARLY in the number of terms rather than as `√k`. Bucket counters
/// and squared gradients are sign-constant. Analysis and measurement:
/// `benches/acc_rounding.py`.
///
/// # Two edges, not one
///
/// **Below.** Anything smaller in magnitude than `1/(2·10^e)` encodes to
/// zero. A property of fixed point, not a loss.
///
/// **Above.** The error is `1/(2·10^e)` and ABSOLUTE only while
/// `|v|·10^e` is exactly representable in f64, i.e. up to about
/// `|v| ≈ 2^53/10^e`. Above that the product itself is rounded and the
/// error becomes RELATIVE.
///
/// | `e` | error | upper bound on `|v|` | sum of 10⁶ sign-constant |
/// |---|---|---|---|
/// | 8 | 5e-09 | ~9e7 | 4.69e-06 |
/// | 12 | 5e-13 | ~9e3 | **1.86e-08** |
/// | 15 | 5e-16 | ~9e0 | 1.86e-08 |
///
/// The right-hand column is ONE draw per row and should be read as an
/// order of magnitude, not a value.
///
/// What follows from the mechanism rather than from the sample: at
/// `e = 12` the encoding error over a million terms is about `3e-10`,
/// while the spacing between adjacent f64 near a sum of order `5e8` is
/// about `1.2e-07`. The encoding shifts the value by less than a
/// hundredth of a step, so the result almost always lands on the SAME
/// float as the exact sum. The error is then the f64 FLOOR — the error
/// of `float()` applied to the exact sum, below which no scheme
/// returning an `f64` can go.
///
/// Occasionally that same tiny shift tips the rounding to the
/// neighbouring float and the error becomes of the order of a step. Over
/// three million-term draws `e = 12` hit the floor exactly; on a fourth,
/// three times the floor. Both outcomes are normal and both are about
/// f64 rounding, not about the scheme.
///
/// This used to say "at `e = 12` it hits the floor" without
/// qualification — a conclusion from a single draw. The correct
/// statement: from `e = 12` the scheme's error drops BELOW the
/// resolution of f64, and raising the scale further is pointless — it
/// only narrows the range.
fn scale_of(pow10: u8) -> f64 {
    10f64.powi(pow10 as i32)
}

/// Validation of an exponent arriving from outside or from a ciphertext.
fn checked_scale(pow10: u8) -> Result<f64, String> {
    if pow10 > MAX_SCALE_POW10 {
        return Err(format!(
            "scale exponent {pow10} is above the {MAX_SCALE_POW10} this \
             encoding allows: past that even a value of one has no exact \
             f64 representation once scaled"
        ));
    }
    Ok(scale_of(pow10))
}

/// How many terms a sum must withstand without overflowing.
///
/// Per-value range checking is NOT enough. Three lawful values of
/// `2.29e299` each pass it on a 1024-bit key, while their sum leaves
/// `n/2` and decrypts as `−4.57e299` — a finite, plausible number of the
/// wrong sign. Exactly the failure the range error message describes,
/// one storey up.
///
/// The sum cannot be checked in place: the terms are encrypted. So
/// headroom is reserved IN ADVANCE — only `x` with
/// `|x| ≤ n/(2·SUM_HEADROOM_TERMS)` is accepted, and `add_many` takes at
/// most `SUM_HEADROOM_TERMS` terms.
///
/// What this pair is NOT: a guarantee by construction. It used to be
/// written that way, and that is wrong — the counter is per call, and
/// the result of `add_many` can be fed into a second one. Two lawful
/// calls give `2^40` terms, and no check sees it: the ciphertext of a
/// sum is indistinguishable from the ciphertext of a term.
///
/// What ACTUALLY keeps a sum inside the group is the relation between
/// the key floor and what is encodable from `f64` at all. With a modulus
/// from 2048 bits the bound on a value is `2^2026` or `2^2027`, while
/// the largest encodable number is about `2^1024`: a thousand bits short
/// of overflow, i.e. `2^1000` terms.
///
/// Two values rather than one for the reason described at
/// `MIN_MODULUS_BITS`: the product of two 1024-bit primes lands on 2048
/// bits and on 2047. A single `2^2027` used to stand here and was
/// refuted by every other key. The test is unaffected: it computes the
/// bound from the ACTUAL modulus length rather than comparing against a
/// literal.
///
/// The counter is kept anyway: it catches a caller passing obviously
/// wrong input — but it must not be called a guarantee.
const SUM_HEADROOM_TERMS: u32 = 1 << 20;

#[pyclass]
struct PublicKey {
    /// `n` as a `rug::Integer` — needed on every encryption.
    n: Integer,
    nn: Integer,
    /// Exponent length in BYTES — half the modulus length.
    ///
    /// Computed by ONE function, `exponent_bytes_for`, from ONE quantity
    /// — the actual length of `n`.
    ///
    /// Putting the formula in a function turned out not to be enough:
    /// the arguments stayed different. `generate_keypair` passed the
    /// requested `bits`, `from_n` passed `n.significant_bits()`, and at
    /// `bits = 1026` the modulus came out at 1025 bits, giving 520 bytes
    /// at the owner and 512 at the peer. The test against that was green
    /// because it stood at `bits = 1024`, where the two coincide by
    /// accident.
    exponent_bytes: usize,
    /// Precomputed powers of `hs` — see `fast::WINDOW_BITS`.
    ///
    /// Held in the key rather than built per message: that is the whole
    /// point. A peer key is assembled once and lives for the session,
    /// and the table with it.
    ///
    /// `hs` is NOT stored as a separate field: it is the first power of
    /// the zeroth window. Holding both forms would mean holding state
    /// that can drift, and `hs = h^n mod n²` is derived HERE, from `n`
    /// alone.
    ///
    /// A claim about LAYOUT stood here twice — first "it is
    /// `table[0][0]`", then "`table[0][1]`" — and both times it stopped
    /// being true silently, on a change to the layout. Entries are no
    /// longer indexed from outside at all: the row is stored as words
    /// and read in full (`fast::WindowTable`).
    table: fast::WindowTable,
}

#[pymethods]
impl PublicKey {
    /// Assemble a public key from ONE `n`, deriving `hs` in place.
    ///
    /// This is the point of the technique: the encrypting side does not
    /// receive `hs` from outside and therefore need not trust it.
    /// Verifying an imported `hs` by computation is impossible — a
    /// smoothness probe with bound `B` certifies only `√B` of work while
    /// costing `π(B)·|n|` exponentiations.
    ///
    /// A poisoned modulus still yields a poisoned `hs`, however
    /// diligently derived — but that is not cured HERE. We check what
    /// everyone checks: oddness and length (`keys::validate_public`,
    /// where the reasoning for checking no more lives).
    ///
    /// Deriving `hs` costs 0.030 s at `|n| = 3072`, so a peer key is
    /// assembled ONCE and kept, not rebuilt per message.
    ///
    /// The sign of `h` is not checked here: that needs `p` and `q`,
    /// which the encrypting side does not have. With an honest `n` the
    /// sign is correct by construction; with a dishonest one it is the
    /// least of the troubles.
    #[staticmethod]
    fn from_n(py: Python<'_>, raw: &[u8]) -> PyResult<PublicKey> {
        // The length is cut off by RAW BYTES before anything is
        // computed. The order here is the point of the check.
        //
        // Previously `n²` was computed before `validate_public` and
        // outside `allow_threads`. The `MAX_MODULUS_BITS` bound exists
        // precisely against denial of service, but stood AFTER the most
        // expensive operation, and that operation ran with the GIL held.
        // Measured on input from a peer: 64 MB instead of a modulus —
        // 4.07 s during which the interpreter executes nothing at all,
        // `SIGINT` handler included. Plus a twofold memory amplification
        // at a length the attacker chooses.
        //
        // Filtering on `raw.len()` does not even require parsing the
        // number. Everything after this runs with the GIL released.
        let limit_bytes = (keys::MAX_MODULUS_BITS as usize + 7) / 8;
        if raw.len() > limit_bytes {
            return Err(PyValueError::new_err(format!(
                "modulus of {} bytes is longer than the {limit_bytes} bytes \
                 that {} bits allow",
                raw.len(),
                keys::MAX_MODULUS_BITS,
            )));
        }
        let n = Integer::from_digits(raw, Order::MsfBe);
        if n.is_even() {
            return Err(PyValueError::new_err("modulus must be odd"));
        }
        let (nn, hs) = py
            .allow_threads(|| {
                keys::validate_public(&n)?;
                let nn = Integer::from(&n * &n);
                derive_hs_for(&n, None).map(|hs| (nn, hs))
            })
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let exponent_bytes = exponent_bytes_for(n.significant_bits());
        let table = py
            .allow_threads(|| build_window_table(&hs, &nn, windows_for(exponent_bytes)));
        Ok(PublicKey {
            n,
            nn,
            exponent_bytes,
            table,
        })
    }

    /// The modulus in bytes — the only thing that travels to a peer.
    fn modulus_bytes(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.n.to_digits::<u8>(Order::MsfBe)).unbind()
    }

    /// Exponent length in bits.
    ///
    /// Exposed so it can be checked. Judging it by collisions among
    /// ciphertexts does not work: measured, a 64-bit exponent produces
    /// no collision in six hundred encryptions, while its strength is
    /// already `2^32` — minutes of work. Check the number, not a
    /// consequence of it.
    #[getter]
    fn exponent_bits(&self) -> usize {
        self.exponent_bytes * 8
    }

    /// The largest accepted plaintext in magnitude, in bits: `n/2`
    /// shrunk by `SUM_HEADROOM_TERMS`.
    ///
    /// Exposed so the headroom can be checked BY NUMBER rather than by
    /// hunting for a value the check will reject. At the 2048-bit floor
    /// the headroom is `2^2026`–`2^2027` (depending on whether the
    /// product landed on 2048 bits or 2047), while the largest number
    /// encodable from `f64` at all is about `2^1024`: the range check
    /// CANNOT fire at that combination.
    ///
    /// It stands anyway, deliberately: key length and scale are both
    /// configurable, and a defence against one combination is not a
    /// defence against another.
    #[getter]
    fn plaintext_bound_bits(&self) -> u32 {
        plaintext_bound(&self.n).significant_bits()
    }
}

#[pyclass]
struct SecretKey {
    inner: secret::Decryptor,
    /// The witness that `keys::validate_private` ran.
    ///
    /// Not decoration: the field cannot be constructed outside `keys`,
    /// so a `SecretKey` assembled without validation does not COMPILE.
    /// A test would not do — on honest input a validated and an
    /// unvalidated key are identical.
    _validated: keys::Validated,
}

/// Encode a float as an integer at the given scale.
///
/// A refusal rather than a silent zero: `Integer::from_f64` returns
/// `None` on `NaN` and `±inf`, and `unwrap_or_default()` turned those
/// into a credible zero that then travelled into the sum. A gap in a
/// feature column is ordinary input, not an exotic case.
fn encode(value: f64, scale: f64) -> Result<Integer, String> {
    if !value.is_finite() {
        return Err(format!(
            "value {value} is not finite: NaN and infinities have no \
             encoding, and turning them into zero would put a plausible \
             number into the sum"
        ));
    }
    let scaled = (value * scale).round();
    if !scaled.is_finite() {
        return Err(format!(
            "value {value:e} overflows to infinity once scaled by {scale:e}"
        ));
    }
    Integer::from_f64(scaled)
        .ok_or_else(|| format!("value {value:e} has no integer encoding"))
}

/// The inverse of `encode`.
///
/// A refusal, not `unwrap_or(0.0)`. The paired function exists precisely
/// so that a non-finite value does not become a credible zero — and a
/// silent zero used to sit here on any unparsed string.
fn decode_integer(m: &Integer, scale: f64) -> Result<f64, String> {
    let text = m.to_string();
    let scaled: f64 = text
        .parse()
        .map_err(|_| format!("plaintext {text} is not a decimal number"))?;
    if !scaled.is_finite() {
        return Err(format!(
            "plaintext of {} digits does not fit a float: the sum has \
             outgrown the encoding, and returning a finite number here \
             would hide that",
            text.trim_start_matches('-').len()
        ));
    }
    Ok(scaled / scale)
}

/// Split a blob: the first byte is the scale exponent, the rest is the
/// ciphertext, most significant byte first.
///
/// A refusal, not a guess. An empty blob and an unknown exponent are
/// input that is NOT a ciphertext under this scheme, and accepting it by
/// substituting a default would mean returning a plausible number at the
/// wrong scale.
fn split_blob(blob: &[u8]) -> Result<(u8, Integer), String> {
    let (head, body) = blob.split_first().ok_or_else(|| {
        "ciphertext is empty: it must start with a scale exponent byte"
            .to_string()
    })?;
    checked_scale(*head)?;
    Ok((*head, Integer::from_digits(body, Order::MsfBe)))
}

/// Assemble a blob: the exponent, then the ciphertext.
fn join_blob(pow10: u8, cipher: &Integer) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(1 + (cipher.significant_bits() as usize + 7) / 8);
    out.push(pow10);
    out.extend_from_slice(&cipher.to_digits::<u8>(Order::MsfBe));
    out
}

/// The largest accepted plaintext in magnitude: `n/2` shrunk by
/// `SUM_HEADROOM_TERMS`.
///
/// Computed by ONE function for both the encryption predicate and the
/// getter. Kept apart, a mutation of the multiplier in the predicate
/// passed the whole suite — the getter kept returning the right number.
fn plaintext_bound(n: &Integer) -> Integer {
    Integer::from(n / (2u32 * SUM_HEADROOM_TERMS))
}

/// Exponent length in bytes, from the ACTUAL modulus length.
///
/// One function and one argument, for the reason described at
/// `PublicKey::exponent_bytes`.
fn exponent_bytes_for(modulus_bits: u32) -> usize {
    ((modulus_bits / 2 + 7) / 8) as usize
}

/// How many values of `x` to try before giving up.
///
/// On an honest modulus unusable values are a handful, so exhausting the
/// budget points at the modulus rather than at bad luck.
const HS_ATTEMPTS: u32 = 64;

/// Derive `hs` for a modulus, optionally with the owner's primes.
///
/// The owner checks the sign of `h` with a Jacobi symbol; a party
/// holding only `n` cannot.
fn derive_hs_for(
    n: &Integer,
    owner: Option<(&Integer, &Integer)>,
) -> Result<Integer, keys::KeyError> {
    let mut rng = rand::thread_rng();
    let width = ((n.significant_bits() + 7) / 8) as usize;
    for _ in 0..HS_ATTEMPTS {
        let mut raw = vec![0u8; width];
        rng.fill(&mut raw[..]);
        let candidate = Integer::from_digits(&raw, Order::MsfBe) % n;
        let derived = match owner {
            Some((p, q)) => keys::derive_h_checked(&candidate, p, q, n),
            None => keys::derive_h(&candidate, n),
        };
        let h = match derived {
            Ok(h) => h,
            // Outside `[2, n−2]`, not coprime, or the wrong sign — take
            // the next one.
            Err(keys::KeyError::BadX)
            | Err(keys::KeyError::HNotAntiResidue) => continue,
            Err(other) => return Err(other),
        };
        match keys::derive_hs(&h, n) {
            Ok(hs) => return Ok(hs),
            Err(keys::KeyError::DegenerateHs) => continue,
            Err(other) => return Err(other),
        }
    }
    Err(keys::KeyError::NoUsableX)
}

/// Generate a key pair with SAFE primes and validate it.
#[pyfunction]
#[pyo3(signature = (bits = 3072))]
fn generate_keypair(
    py: Python<'_>,
    bits: u32,
) -> PyResult<(PublicKey, SecretKey)> {
    if bits < keys::MIN_MODULUS_BITS {
        return Err(PyValueError::new_err(format!(
            "modulus of {bits} bits is refused: the floor is {} \
             (NIST SP 800-57 puts 112-bit strength at 2048). A shorter \
             key passes every correctness check and factors in \
             microseconds",
            keys::MIN_MODULUS_BITS
        )));
    }
    if bits > keys::MAX_MODULUS_BITS {
        return Err(PyValueError::new_err(format!(
            "modulus of {bits} bits is refused: the ceiling is {}. \
             Generating safe primes that long takes unbounded time with \
             the GIL released, so the call could not be interrupted",
            keys::MAX_MODULUS_BITS
        )));
    }
    let (p_rug, q_rug) = py.allow_threads(|| {
        let half = bits / 2;
        (primes::safe_prime(half), primes::safe_prime(half))
    });
    let validated = keys::validate_private(&p_rug, &q_rug)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let n = Integer::from(&p_rug * &q_rug);
    let nn = Integer::from(&n * &n);
    let hs = py
        .allow_threads(|| derive_hs_for(&n, Some((&p_rug, &q_rug))))
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let exponent_bytes = exponent_bytes_for(n.significant_bits());
    let table =
        py.allow_threads(|| build_window_table(&hs, &nn, windows_for(exponent_bytes)));
    Ok((
        PublicKey {
            n,
            nn,
            exponent_bytes,
            table,
        },
        SecretKey {
            inner: secret::Decryptor::new(&p_rug, &q_rug).ok_or_else(|| {
                PyValueError::new_err(
                    "cannot prepare decryption: the two primes are equal \
                     or not coprime, so the CRT split does not exist",
                )
            })?,
            _validated: validated,
        },
    ))
}

/// The random exponent, drawn ONCE for the two places that need one.
///
/// `encrypt_many` masks a plaintext with `hs^r`, and `rerandomize` masks
/// a finished ciphertext with the same thing. Both need the same length
/// and the same entropy, and neither may quietly get less.
///
/// # Why this is a function and not two matching lines
///
/// The two lines matched, and a review broke them apart in a way no test
/// noticed: filling only the first four bytes of a full-width buffer.
/// The exponent stays `width` bytes long, so it costs exactly what it
/// cost before — and every test passed, including the one whose
/// docstring claimed a short exponent would be thirty times cheaper.
///
/// That claim was wrong about this library specifically. `pow_by_table`
/// is deliberately blind to the VALUES of the exponent digits: it reads
/// every row in full and multiplies at every window, so leading zeros
/// cost the same as anything else. Timing therefore pins the WIDTH of
/// the buffer and can never pin its ENTROPY.
///
/// Not that entropy is beyond measurement altogether: re-randomising one
/// blob about `2^18` times and looking for a duplicate output catches a
/// collapse to 32 bits in seconds. What no practical measurement
/// distinguishes is 64 bits from full — and a collision test is not what
/// a suite should rest on.
///
/// So the property is held structurally instead: there is one function,
/// it fills the whole slice, and shortening it shortens encryption too —
/// where the existing tests do notice.
fn random_exponent(width: usize) -> Vec<u8> {
    let mut raw = vec![0u8; width];
    rand::thread_rng().fill(&mut raw[..]);
    raw
}

/// Encrypt a list of values. Runs across all cores.
#[pyfunction]
#[pyo3(signature = (pk, values, scale_pow10 = DEFAULT_SCALE_POW10))]
fn encrypt_many(
    py: Python<'_>,
    pk: &PublicKey,
    values: Vec<f64>,
    scale_pow10: u8,
) -> PyResult<Vec<Py<PyBytes>>> {
    let (n, nn, table) = (&pk.n, &pk.nn, &pk.table);
    let width = pk.exponent_bytes;
    let bound = plaintext_bound(n);
    let scale = checked_scale(scale_pow10).map_err(PyValueError::new_err)?;
    // `allow_threads` releases the GIL: without it rayon buys nothing.
    let encrypted: Result<Vec<Vec<u8>>, String> = py.allow_threads(|| {
        values
            .par_iter()
            .map(|v| -> Result<Vec<u8>, String> {
                // The exponent is short — half the modulus length. This
                // is the one place where we depart from the original
                // scheme, and its length must not drift silently.
                let raw = random_exponent(width);
                // The exponent is never assembled into an `Integer`: the
                // window digits are read straight from the generator's
                // bytes. Assembling would be not only wasted work but a
                // second place where the exponent length could drift.
                let digits = windows_of(&raw);
                let encoded = match encode(*v, scale) {
                    Ok(value) => value,
                    Err(message) => return Err(message),
                };
                let x = encoded;
                // Plaintext range: `−n/2 ≤ x ≤ n/2`, shrunk by
                // `SUM_HEADROOM_TERMS` to reserve room for a sum.
                //
                // Rewriting encryption, I once lost this check and the
                // refusal went from loud to silent: `1e300` came back as
                // `−4.8e299`.
                //
                // One such check is not enough on its own: it is
                // per-value, while what overflows is the SUM. The
                // headroom covers that — see `SUM_HEADROOM_TERMS`.
                if x.clone().abs() > bound {
                    return Err(format!(
                        "plaintext {v:e} is outside the signed group of \
                         this key once room for a sum of \
                         {SUM_HEADROOM_TERMS} terms is reserved. At the \
                         2048-bit floor no f64 can reach this bound, so \
                         seeing this means the key or the scale changed"
                    ));
                }
                // `g^m = 1 + m·n` with `g = n+1` — one multiplication
                // instead of an exponentiation.
                //
                // A EUCLIDEAN remainder, not a truncated one: with a
                // negative `x`, rug's plain `%` gives a negative `a`, and
                // `to_digits` then writes the magnitude, silently losing
                // the sign.
                //
                // A branch `if x < 0 { x += n }` used to stand here. It
                // did the same thing but was UNOBSERVABLE: switching it
                // off leaves both the round trip and homomorphism green,
                // because `λ` is even, so `(−1)^λ ≡ 1 (mod n²)` and `−C`
                // decrypts exactly as `C`. A branch that cannot be
                // checked looks like a guarantee and is not one; the
                // Euclidean remainder gives the canonical form
                // structurally.
                let a = Integer::from(1 + x * n).rem_euc(nn.clone());
                // `hs^r = (h^r)^n` is a legitimate `n`-th residue, so
                // decryption is unchanged.
                //
                // BY TABLE rather than `pow_mod`: the base is fixed for
                // the whole key and its powers are already computed.
                // `pow_mod` would rebuild its own table per message.
                let b = pow_by_table(table, &digits);
                let c = (a * b) % nn;
                Ok(join_blob(scale_pow10, &c))
            })
            .collect()
    });
    Ok(encrypted
        .map_err(PyValueError::new_err)?
        .into_iter()
        .map(|b| PyBytes::new(py, &b).unbind())
        .collect())
}

/// Add ciphertexts. One call into Rust for the whole batch.
#[pyfunction]
fn add_many(
    py: Python<'_>,
    pk: &PublicKey,
    blobs: Vec<Bound<'_, PyBytes>>,
) -> PyResult<Py<PyBytes>> {
    let nn = &pk.nn;
    if blobs.is_empty() {
        return Err(PyValueError::new_err(
            "add_many needs at least one ciphertext: an empty sum has no \
             encryption under this key, and returning one would be a \
             ciphertext of zero that nobody asked for",
        ));
    }
    // A cap per CALL, not a guarantee: the result can be fed into a
    // second call and the counter starts over. What actually keeps a sum
    // in range — see `SUM_HEADROOM_TERMS`.
    if blobs.len() > SUM_HEADROOM_TERMS as usize {
        return Err(PyValueError::new_err(format!(
            "add_many takes at most {SUM_HEADROOM_TERMS} ciphertexts per \
             call, got {}: past that the reserved headroom stops covering \
             the sum. This is a per-call limit, not a guarantee - chaining \
             calls escapes it, and what actually keeps sums in range is \
             the gap between the key floor and the f64 range",
            blobs.len()
        )));
    }
    // Slices, NOT copies: `as_bytes` borrows the `bytes` object's own
    // buffer. Releasing the GIL is still safe because `blobs` keeps the
    // `Bound` references alive for the whole call and Python `bytes` are
    // immutable — the buffer will not move or be rewritten under us.
    let slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_bytes()).collect();

    // An error, not a panic. `PanicException` inherits `BaseException`,
    // so `except Exception` does NOT catch it: a neighbouring input of
    // the same origin — an empty sum — got a tidy `ValueError`, while a
    // malformed ciphertext killed the process.
    //
    // The multiplication is done HERE rather than through the crate's
    // `oadd`, which validates group membership of BOTH operands, i.e.
    // the accumulator goes through a `gcd` again on every term.
    //
    // The check is range-only: a ciphertext must lie in `[1, n²)`. Zero
    // is refused separately — it is not invertible, so it is not a
    // ciphertext of anything.
    //
    // What this check does NOT do: it does not catch a NON-INVERTIBLE
    // ciphertext. The value `n` falls inside `[1, n²)` yet
    // `gcd(n, n²) ≠ 1`, and a sum containing it is spoiled. The refusal
    // then arrives later, at the key holder, without a term index. This
    // is deliberate: a `gcd` per term would cost more than the whole
    // operation.
    let (total, scale_pow10) = py
        .allow_threads(|| {
            let mut total = Integer::from(1);
            let mut scale_pow10: Option<u8> = None;
            for (index, blob) in slices.iter().enumerate() {
                let (pow10, value) = split_blob(blob).map_err(|message| {
                    format!("ciphertext #{}: {message}", index + 1)
                })?;
                // Adding ciphertexts of different scales means adding
                // different units. The scheme cannot see it: the codes
                // are integers, the sum goes through, and a plausible
                // wrong number comes back. Hence a REFUSAL rather than a
                // rescale: rescaling means multiplying the plaintext,
                // and the plaintext is encrypted.
                match scale_pow10 {
                    None => scale_pow10 = Some(pow10),
                    Some(first) if first != pow10 => {
                        return Err(format!(
                            "ciphertext #{} was encoded with scale 1e{pow10} \
                             while the sum started at 1e{first}: adding them \
                             would produce a plausible wrong number, and \
                             rescaling is impossible on encrypted values",
                            index + 1
                        ))
                    }
                    Some(_) => {}
                }
                if value < 1 || value >= *nn {
                    return Err(format!(
                        "ciphertext #{} is not in [1, n^2) of this key: a \
                         valid ciphertext is an invertible residue modulo \
                         n^2, and this one is not",
                        index + 1
                    ));
                }
                total = total * value % nn;
            }
            Ok((
                total,
                scale_pow10.expect("the batch is non-empty, checked above"),
            ))
        })
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &join_blob(scale_pow10, &total)).unbind())
}

/// The width, in bits, that an encoded scalar must fit.
///
/// Every scalar exponentiation runs at EXACTLY `SCALAR_BITS + 2` bits,
/// whatever the scalar — see `multiply_many`. The bound therefore has to
/// be a constant of the scheme rather than something derived per call:
/// derived from the scale, it would vary between calls, and the width of
/// the exponent is what an observer can see.
///
/// 64 bits covers everything the encoding can produce for a sane scalar:
/// at the maximum scale `1e18` it admits `|k| ≤ 18.4`, and at the default
/// `1e8` it admits `|k| ≤ 1.8e11`. A scalar outside that is refused.
const SCALAR_BITS: u32 = 64;

/// Multiply ciphertexts by KNOWN scalars: `E(x) → E(k·x)`.
///
/// An additively homomorphic scheme can do this — `E(x)^k = E(k·x)` —
/// and it is what lets a party compute a squared distance between two
/// distributions without showing either of them.
///
/// # The scale is handled here, not by the caller
///
/// The scalar is an integer under encryption, so the product arrives at
/// the SUM of the two scales. The `phe`-based code this replaces returns
/// that product with the original scale byte and says in its docstring
/// that "the caller must divide" — which is the plausible-wrong-number
/// failure this library exists to refuse. Here the scale travels in the
/// blob, so the header is updated and `decrypt` divides by the right
/// thing without being told.
///
/// `scalar_scale_pow10` defaults to the scale of the ciphertext, so the
/// common case is `8 + 8 = 16`. Past `MAX_SCALE_POW10` it is a refusal.
///
/// Two consequences worth knowing before they are discovered as errors:
///
/// * **multiplication does not compose at the default.** A second
///   multiplication would be `16 + 16 = 32`, refused (the scalar scale
///   defaults to the CIPHERTEXT's, which is already 16 by then). Chaining
///   means
///   lowering `scalar_scale_pow10`;
/// * **the products cannot be added to ordinary ciphertexts.**
///   `add_many` refuses a mixed batch, so companions have to be
///   encrypted at the product's scale: `encrypt_many(pub, values,
///   scale_pow10=16)`.
///
/// # The exponent is SECRET, so it is the secret-exponent path
///
/// In the caller this feature exists for, the scalar is the secret: the
/// responder multiplies by its own bucket share, the very quantity the
/// exchange hides. So this is `secure_pow_mod`, for the same reason
/// decryption is (`secret.rs`), and not the windowed `pow_mod`.
///
/// That alone hides the exponent's VALUE but not its LENGTH, and the
/// length of `k` is roughly the magnitude of the scalar. So the exponent
/// is offset to a fixed width: with `|k| < 2^B`,
///
/// ```text
/// k + 3·2^B  ∈  (2^(B+1), 2^(B+2))
/// ```
///
/// which is `B+2` bits for EVERY `k`, negative ones included. The offset
/// is then divided out — `E(x)^(k+3·2^B) · (E(x)^(3·2^B))^{-1}` — at the
/// cost of a second exponentiation of the same fixed width and one
/// modular inversion. The inversion is not constant time, but what it
/// inverts is a power of the ciphertext the caller was given, which the
/// other side already holds; the secret here is only `k`.
///
/// # A scalar that encodes to zero is REFUSED
///
/// `round(1e-9 · 1e8) = 0`, and `E(x)^0 = 1`: the data is destroyed and
/// the output becomes a two-byte constant that anyone can recognise. In
/// the intended caller the scalar is a bucket share, so a vanishing one
/// means an empty bucket — and publishing "this bucket is empty" as a
/// distinctive blob is a leak, not a result. An exact zero is refused
/// too, and for the same reason: encrypt a zero if that is what you
/// want.
#[pyfunction]
#[pyo3(signature = (pk, blobs, scalars, scalar_scale_pow10 = None))]
fn multiply_many(
    py: Python<'_>,
    pk: &PublicKey,
    blobs: Vec<Bound<'_, PyBytes>>,
    scalars: Vec<f64>,
    scalar_scale_pow10: Option<u8>,
) -> PyResult<Vec<Py<PyBytes>>> {
    if blobs.len() != scalars.len() {
        return Err(PyValueError::new_err(format!(
            "multiply_many got {} ciphertexts and {} scalars: they are \
             paired by position, and a length mismatch means the pairing \
             the caller intended is not the one that would happen",
            blobs.len(),
            scalars.len()
        )));
    }
    let nn = &pk.nn;
    // `|k| < 2^SCALAR_BITS`, so `k + offset` is always `SCALAR_BITS + 2`
    // bits wide.
    let bound = Integer::from(1) << SCALAR_BITS;
    let offset = Integer::from(3) * &bound;

    let slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_bytes()).collect();

    let produced = py
        .allow_threads(|| {
            let mut out: Vec<Vec<u8>> = Vec::with_capacity(slices.len());
            for (index, (blob, scalar)) in
                slices.iter().zip(scalars.iter()).enumerate()
            {
                let (pow10, cipher) = split_blob(blob).map_err(|message| {
                    format!("ciphertext #{}: {message}", index + 1)
                })?;
                if cipher < 1 || cipher >= *nn {
                    return Err(format!(
                        "ciphertext #{} is not in [1, n^2) of this key",
                        index + 1
                    ));
                }

                let scalar_pow10 = scalar_scale_pow10.unwrap_or(pow10);
                let product_pow10 = u32::from(pow10) + u32::from(scalar_pow10);
                if product_pow10 > u32::from(MAX_SCALE_POW10) {
                    return Err(format!(
                        "scalar #{}: the product lands at scale 1e{product_pow10} \
                         (1e{pow10} of the ciphertext times 1e{scalar_pow10} of \
                         the scalar), past the 1e{MAX_SCALE_POW10} this encoding \
                         allows. Lower scalar_scale_pow10 - the product's scale \
                         is the SUM of the two, so multiplication does not \
                         compose at the default",
                        index + 1
                    ));
                }
                let scalar_scale = checked_scale(scalar_pow10)?;
                let encoded = encode(*scalar, scalar_scale).map_err(
                    |message| format!("scalar #{}: {message}", index + 1),
                )?;
                if encoded == 0 {
                    return Err(format!(
                        "scalar #{} encodes to zero at scale {scalar_scale:e} \
                         (it is {scalar:e}): the product would be the constant \
                         1, destroying the value and marking the result as \
                         recognisably zero to anyone who sees it. Encrypt a \
                         zero if that is the intent",
                        index + 1
                    ));
                }
                if encoded.clone().abs() >= bound {
                    return Err(format!(
                        "scalar #{} encodes to {} digits, past the \
                         {SCALAR_BITS}-bit width every scalar exponentiation \
                         runs at. The width is fixed on purpose: a per-scalar \
                         width would show the magnitude of the scalar in the \
                         timing",
                        index + 1,
                        encoded.to_string().trim_start_matches('-').len()
                    ));
                }

                // `k + 3·2^B` — always positive, always `B+2` bits.
                let shifted = Integer::from(&encoded + &offset);
                let raised = cipher.clone().secure_pow_mod(&shifted, nn);
                let planted = cipher.secure_pow_mod(&offset, nn);
                let undo = planted.invert(nn).map_err(|_| {
                    format!(
                        "ciphertext #{} is not invertible modulo n^2: it \
                         shares a factor with n, so it is not a ciphertext \
                         under this key",
                        index + 1
                    )
                })?;
                let product = raised * undo % nn;

                out.push(join_blob(product_pow10 as u8, &product));
            }
            Ok(out)
        })
        .map_err(PyValueError::new_err)?;

    Ok(produced
        .into_iter()
        .map(|raw| PyBytes::new(py, &raw).unbind())
        .collect())
}

/// Re-randomise ciphertexts: same plaintext, different bytes.
///
/// Each blob is multiplied by `hs^{r}` with a fresh `r` — an independent
/// encryption of zero — so the plaintext is untouched while the
/// ciphertext is distributed as a fresh one.
///
/// # What it is for
///
/// The homomorphic operations here are DETERMINISTIC. `add_many` of the
/// same terms returns the same bytes, a one-term sum returns its input
/// verbatim, and `multiply_many` returns exactly `E(x)^k`. Whoever knows
/// the inputs can therefore confirm a guess about the operation offline
/// by recomputing it — which terms went into a sum, or what the scalar
/// was.
///
/// That matters only when the RESULT leaves the process. Hence a
/// separate call rather than something the operations do for you:
///
/// * inside a computation the property buys nothing, and it costs one
///   full-length exponentiation per ciphertext — about the price of an
///   encryption;
/// * the library cannot know which of your ciphertexts are about to be
///   transmitted, and you do.
///
/// A flag on the operations was considered and rejected. On by default,
/// everyone pays for a property most calls do not need — the analytics
/// exchange this was written for would pay for nothing at all, since it
/// sums products together with its own fresh noise and the result is
/// already not a function of what arrived. Off by default, it would be
/// left off exactly where it costs most.
///
/// # This is not a substitute for noise
///
/// Re-randomising hides WHICH ciphertext this is. It does not hide the
/// value and it does not stop an observer who can decrypt: if the party
/// receiving the result holds the private key, they read the plaintext,
/// and no amount of re-randomising changes that.
///
/// The scale byte passes through unchanged — re-randomising is not an
/// arithmetic operation and must not look like one.
#[pyfunction]
fn rerandomize(
    py: Python<'_>,
    pk: &PublicKey,
    blobs: Vec<Bound<'_, PyBytes>>,
) -> PyResult<Vec<Py<PyBytes>>> {
    let (nn, table) = (&pk.nn, &pk.table);
    let width = pk.exponent_bytes;
    let slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_bytes()).collect();

    let produced: Result<Vec<Vec<u8>>, String> = py.allow_threads(|| {
        slices
            .par_iter()
            .enumerate()
            .map(|(index, blob)| -> Result<Vec<u8>, String> {
                let (pow10, cipher) = split_blob(blob).map_err(|message| {
                    format!("ciphertext #{}: {message}", index + 1)
                })?;
                if cipher < 1 || cipher >= *nn {
                    return Err(format!(
                        "ciphertext #{} is not in [1, n^2) of this key",
                        index + 1
                    ));
                }
                // The SAME function encryption draws its exponent from,
                // not a matching pair of lines: matching lines were
                // broken apart once, by filling only four bytes of a
                // full-width buffer, and nothing noticed.
                let raw = random_exponent(width);
                let digits = windows_of(&raw);
                let masked = cipher * pow_by_table(table, &digits) % nn;
                Ok(join_blob(pow10, &masked))
            })
            .collect()
    });

    Ok(produced
        .map_err(PyValueError::new_err)?
        .into_iter()
        .map(|raw| PyBytes::new(py, &raw).unbind())
        .collect())
}

/// Decrypt one ciphertext. The scale is taken from the blob.
#[pyfunction]
fn decrypt(sk: &SecretKey, blob: &[u8]) -> PyResult<f64> {
    let (scale_pow10, cipher) =
        split_blob(blob).map_err(PyValueError::new_err)?;
    let scale = scale_of(scale_pow10);
    let plain = sk.inner.decrypt(&cipher).ok_or_else(|| {
        PyValueError::new_err(
            "not a ciphertext under this key: a valid one lies in \
             [1, n^2) and is coprime with n. A ciphertext made under a \
             different key usually lands here, but not always - there is \
             no pairing check, and there cannot be one from n alone",
        )
    })?;
    decode_integer(&plain, scale).map_err(PyValueError::new_err)
}

#[pymodule]
fn paillier(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // The version comes from `Cargo.toml` AT BUILD TIME rather than
    // being retyped: two copies of a number drift apart silently, and a
    // drifted version is worse than none — it lies about which code is
    // in `site-packages`. The module is placed there as a file, without
    // package metadata, so there is nobody to ask via
    // `importlib.metadata`.
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<PublicKey>()?;
    m.add_class::<SecretKey>()?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_many, m)?)?;
    m.add_function(wrap_pyfunction!(add_many, m)?)?;
    m.add_function(wrap_pyfunction!(multiply_many, m)?)?;
    m.add_function(wrap_pyfunction!(rerandomize, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every byte of the exponent must actually be drawn.
    ///
    /// This exists because of a specific break that nothing else could
    /// see. Filling only the first four bytes of a full-width buffer
    /// leaves the exponent the same LENGTH — so it costs the same, and
    /// the Python test that measures the cost against an encryption
    /// stays green — while its entropy collapses to 32 bits and the
    /// guess-and-recompute attack `rerandomize` exists to close reopens
    /// at 2^32 offline exponentiations.
    ///
    /// Timing cannot catch it, and not by accident: `pow_by_table` reads
    /// every row in full and multiplies at every window precisely so
    /// that the digit VALUES do not affect the cost. The property has to
    /// be checked here, on the bytes.
    ///
    /// The criterion is per POSITION, not "some byte is non-zero": the
    /// break leaves the first four bytes perfectly random, so a check on
    /// the buffer as a whole passes. Over 200 draws the chance that a
    /// given position is zero every time is `(1/256)^200`.
    #[test]
    fn the_whole_exponent_is_drawn() {
        const WIDTH: usize = 128;
        const DRAWS: usize = 200;

        let mut seen_non_zero = vec![false; WIDTH];
        for _ in 0..DRAWS {
            let raw = random_exponent(WIDTH);
            assert_eq!(raw.len(), WIDTH, "the exponent changed length");
            for (position, byte) in raw.iter().enumerate() {
                if *byte != 0 {
                    seen_non_zero[position] = true;
                }
            }
        }

        let dead: Vec<usize> = seen_non_zero
            .iter()
            .enumerate()
            .filter(|(_, live)| !**live)
            .map(|(position, _)| position)
            .collect();
        assert!(
            dead.is_empty(),
            "byte positions {dead:?} were zero in all {DRAWS} draws: the \
             exponent keeps its width but not its entropy, which no timing \
             measurement can detect"
        );
    }

    /// Two draws must differ — a constant would pass the check above.
    #[test]
    fn two_exponents_differ() {
        assert_ne!(random_exponent(64), random_exponent(64));
    }
}
