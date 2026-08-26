# Changelog

## 0.3.0 — 2026-08-26

**BREAKING.** The blob now starts with a byte holding the power-of-ten
scale exponent, and ciphertexts from 0.2.0 cannot be decrypted by this
version.

### The encoding scale is configurable

`encrypt_many(pub, values, scale_pow10=8)`, values from 0 to 18.

The scale is a property of the CIPHERTEXT, not of the call, and that is
not decoration. A scale mismatch produces not a refusal but a plausible
wrong number: same codes, same length, just a result smaller by `10^Δ`.
So `decrypt` reads the scale from the blob itself, and `add_many`
**refuses** a batch that mixes scales. This matters especially for a
party that only encrypts: it builds a peer key from `n` alone, where no
scale exists — configured "on the side", it would silently disagree with
the key holder.

The cost is one byte per ciphertext: 512 → 513.

At `scale_pow10 = 12` the sum error over a million sign-constant terms
falls from 4.69e-06 to **1.86e-08** — the `f64` floor, i.e. the error of
`float()` applied to the exact sum. The price is a narrower input range,
from `|v| ≲ 9e7` down to `≲ 9e3`. The default stays at `8`: a wide range
is a sensible default, narrowing it for accuracy is the caller's call.

### Window width 4 → 6 bits

Single-threaded encryption **686 → 980 ops/s (×1.43)**, batched
4403 → 6500–6700.

Profiling showed that encryption is 98.2 % multiplications inside
`pow_by_table`, so the operation is essentially `windows + 2` modular
multiplications and nothing else. Six bits is where the gain is still
nearly linear in the window count while the table (5.6 MB per key) stays
comfortably below the cache.

Constant-time reading is preserved; its cost was re-measured at 1–5 %.

An earlier explanation of where the time went — "it is the modular
multiplication, and Montgomery form on limbs would fix it" — **turned
out to be wrong** and has been replaced. Montgomery on `mpn_*` with no
allocations gives 1.10–1.20, not 2: REDC costs almost as much as
division, because division in GMP at these lengths is already
subquadratic.

### Fixed

- The window count was computed as `bytes * 2` in two places — a formula
  correct only for a four-bit window. Now a single function,
  `windows_for`.
- The same `bytes * 2` sat in `benches/exponent_length.rs` and printed
  twice as many windows as were actually used.
- Three tests that parsed a blob as one integer kept PASSING after the
  header byte was introduced, checking garbage: their assertions are of
  the "not equal" and "not one" kind, and garbage satisfies those.
  Parsing was moved into `cipher_int`.

## 0.2.0 — 2026-08-26

The first release where the cryptography is our own. The package used to
be glue on top of the `fast-paillier` crate; now the scheme, key
generation, encryption, addition and decryption are written here, and
the crate remains only as a test oracle.

### The scheme

- Encryption with a SHORT EXPONENT: `c = (1 + m·n) · hs^r mod n²`, where
  `hs = h^n`, `h = −x² mod n`, `|r| = |n|/2` — the Damgård–Jurik
  variant. This adds a security assumption on top of DCRA; the analysis
  is in `docs/short-exponent-security.md`.
- Our own safe-prime generation with a double sieve.
- CRT decryption through `mpz_powm_sec`: the exponent there derives from
  `λ`, the long-lived secret of the key.
- A window table for the fixed base: 256 multiplications instead of
  ~1280 per exponentiation.

### Side channels

- **Closed**: the exponent-weight channel. A multiplication happens at
  every window, and the zero entry holds `n² + 1` rather than `1` (a
  single-limb one multiplies in `O(limbs)` and does not close the leak).
- **Closed**: the cache channel. The table row is laid out in 64-bit
  words, read in full, and the entry is selected with an arithmetic mask
  and no branches. The cost is 1–3 % on the exponentiation, invisible
  end to end.
- **Open**: the leading-zeros channel — about 0.36 bits out of 1024 at
  the window width of this release. Named, measured, guarded by a test
  that watches it does not grow; the only known cure is Montgomery form,
  rejected on measurement.

### Refusals instead of a plausible number

- A foreign modulus is cut off by RAW BYTE length, before any
  arithmetic. Previously `n²` was computed before the check and with the
  GIL held: 64 MB from a peer bought 4.07 seconds of complete deafness.
- `NaN`, `±inf`, overflow when scaling, an empty sum, a foreign
  ciphertext, an even modulus — all refusals, not results.
- The key is validated when assembled; skipping validation is a COMPILE
  error (a `keys::Validated` witness with a private field).

### Encoding

- Fixed point, scale `1e8`, rounding TO NEAREST. Truncation toward zero
  yields an error that grows LINEARLY on sign-constant data instead of
  as `√k`: 5.00e-04 against 1.17e-06 over 100 000 terms.

### Speed (2048-bit key, one machine)

| | ops/s per thread | addition | decryption |
|---|---|---|---|
| this release | 686 | 6.7 µs | 3.65 ms |

Decryption is slower than it could be by design, not by algorithm: with
a plain `mpz_powm` it would be about 2.4 ms, but the exponent derives
from the long-lived secret.

### Tooling

- `pytest.ini`: without it, `pytest` at the repository root collected
  ZERO tests — the files are named after their subject, not `test_*.py`.
- `tests/docs_references.py`: everything the documentation names must
  exist AND be in the git index.
- Benchmarks in `benches/`: the cost of constant-time reading, the cost
  of `mpz_powm_sec`, the effect of exponent length, the rounding rule,
  and error accumulation on symmetric and on sign-constant input.

## 0.1.0

A Python binding on top of `fast-paillier`: `float` encoding,
serialisation, parallel encryption.
