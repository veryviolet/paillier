# Changelog

## 0.5.0 — 2026-08-27

Additive only. Nothing existing changes behaviour, and ciphertexts keep
their format.

### `multiply_many` — multiplication by a known scalar

`E(x) → E(k·x)`, which an additively homomorphic scheme gives for free
and which this library did not expose. It is what lets a party compute a
squared distance between two distributions without showing either of
them, and its absence was the one thing keeping a consumer on another
library.

**The scale is handled here rather than by the caller.** A product lands
at the sum of the two scales, and the returned blob says so in its
header, so `decrypt` divides by the right thing without being told. The
`phe`-based code this replaces returns the product with the ORIGINAL
scale byte and states in its own docstring that the caller must divide —
which is the plausible-wrong-number failure this library exists to
refuse.

Two consequences are worth knowing before they are met as errors:
multiplication does not compose at the default (`16 + 16 = 32`, refused
— chaining means lowering `scalar_scale_pow10`), and a product cannot be
added to an ordinary ciphertext, because `add_many` refuses a mixed
batch. Companions are encrypted at the product's scale.

**A scalar that encodes to zero is refused, an exact zero included.**
`E(x)^0` is the constant `1`: the value is destroyed and the output
becomes a two-byte blob anyone can recognise. Where the scalar is a share
or a weight, a vanishing one means "this bucket is empty", and shipping
that as a distinctive blob is a leak rather than a result.

**The exponent is secret, so this is the secret-exponent path** — the
same `mpz_powm_sec` decryption uses, and for the same reason: in the
caller this exists for, the scalar is the responder's own bucket share.

That alone hides the exponent's value but not its length, and its length
is the magnitude of the scalar. So the exponent is offset to a constant
width — with `|k| < 2^64`, `k + 3·2^64` is 66 bits for every `k`,
negative ones included — and the offset is divided out afterwards. The
cost is a second exponentiation of the same width and one modular
inversion; the width is the reason a scalar past `|k| ≤ 1.8e11` at the
default scale is refused rather than run wider.

The sign is hidden by the same construction: the offset makes every
exponent positive, so both exponentiations and the inversion run
unconditionally and there is no branch on the sign at all.

### `rerandomize` — same plaintext, different bytes

Every homomorphic operation here is deterministic: `add_many` of the same
terms returns the same bytes, a one-term sum returns its input verbatim,
and `multiply_many` returns exactly `E(x)^k`. Whoever knows the inputs
can confirm a guess about the operation by recomputing it — which terms
went into a sum, or what the scalar was.

`rerandomize(pub, blobs)` multiplies each ciphertext by a fresh encryption
of zero, so the value is unchanged and the bytes are not recomputable. It
costs one encryption per ciphertext, because that is what it is.

A separate call rather than a flag on the operations. It matters only
when the result LEAVES, and the library cannot know which ciphertexts are
about to be sent while the caller can. A flag on by default charges
everyone for a property most calls do not need — the analytics exchange
this was written for would pay for nothing, since it sums products with
its own fresh noise; off by default it would be left off exactly where it
costs most.

It hides WHICH ciphertext, not the value. Against a party holding the
private key it does nothing.

### What the fixed width does NOT protect

The product is `E(x)^k` and nothing else — a deterministic function of the
input ciphertext and the scalar. Anyone who sees both recovers `k` by
trying candidates, and a scalar that is a share or a small weight has
few worth trying. So the constant-width exponent guards a side door —
timing, available to a neighbour on the same machine — while this one
stands open, and the documentation says so rather than letting the
machinery imply otherwise.

What closes it is `rerandomize` before transmitting, or summing the
products with something the other side did not send. The analytics exchange this was
built for does exactly that, which is why the library does not: it
cannot know which of a caller's ciphertexts are about to leave.

### What was considered and NOT done

Rerandomising the output of `add_many`. It is byte-stable — the same
terms give the same bytes, and a one-term sum returns its input verbatim
— and `phe` obfuscates on serialisation precisely to stop that.

An adversarial review refuted the harm in both real consumers: in the
tree trainer the party that would run the test holds the private key and
decrypts every aggregate anyway, and in the analytics exchange the
responder folds its own encrypted noise into the reply, so the reply is
not a deterministic function of what was sent. The property is worth
having and may come later; it is not being sold as a fix for a leak that
was not demonstrated.

## 0.4.0 — 2026-08-27

Ciphertexts are unchanged and interoperate with 0.3.0 in both
directions: the arithmetic below is a different way to compute the same
residue, not a different scheme.

### The leading-zeros timing channel is closed

This was the last channel the documentation named as open. While the low
windows of the secret exponent were zero, the accumulator stayed an
`Integer` equal to one — a single limb, cheap to multiply by. Measured:
**−6.33 µs per leading zero** at fixed weight.

It is closed by a change of container rather than of value. The
accumulator and the window table now live in fixed-width limb buffers
(`mpn_*` instead of `mpz_*`), where a product of two `k`-limb operands
costs the same whatever they hold, because nothing looks at how many
leading zeros there are. Reduction modulo `n²` would otherwise need a
division, which *is* value-dependent, so the arithmetic is in
**Montgomery form**: one multiplication and one branch-free conditional
subtraction.

Measured after the change: **−0.2 µs per leading zero**, thirty-one
times smaller and indistinguishable from the residual slope of the
already-closed weight channel.

The guard was tightened at the same time, from 15.0 to 2.5 µs per zero.
At 15.0 it stayed green under a mutation that reintroduced a branch on
the secret digit and drove the slope to −4.58 — a threshold written for
an open channel does not guard a closed one. The weight channel keeps
its own threshold of 1.0: merging the two onto a single number would
have tightened one test and quietly loosened the other.

### The cache-address channel is guarded at last

It was described in the documentation as closed and measured, alongside
the other two. Closed it is; measured it cannot be. Reading one table
entry and reading all sixty-four produce identical output, and the
difference in cost is inside the noise of the slope tests — reverting
`select_entry` to the address-dependent form left every test in the
repository green.

`tests/constant_time_shape.py` now checks the shape of that function:
that no address is derived from the secret digit, and that the loop
covers the whole row. A source-level tripwire rather than a proof, and
the documentation now says which of the three channels is guarded how.

### `unsafe`, in one module and nowhere else

`mpn_*` is a C API, so this crate is no longer free of `unsafe`. It
carries `#![deny(unsafe_code)]`, lifted only in `src/mont.rs`: four GMP
calls over buffers whose lengths are asserted in safe Rust immediately
before each call, with no raw pointers stored anywhere and no allocation
inside the blocks.

What changed is whose responsibility that arithmetic is. It was `rug`'s
and GMP's, and about 150 lines of it are now ours. The built wheel was
never free of unsafe code — it statically contains GMP — and nothing in
the documentation claimed otherwise. See `NOTICE.md`.

### Faster, secondarily

Single-threaded encryption **1010 → 1066 ops/s**, batched 6334 → 6855,
measured as an A/B of the two builds on one machine with one script. At
the level of the exponentiation itself the gain is larger — 958 → 832 µs
at 2048 bits — and end to end it is diluted by encoding, serialisation
and the GIL.

Montgomery form had been implemented once before, over `rug::Integer`,
and removed on measurement: assembled from `mpz` operations it allocates
at every step and loses by a factor of 1.19. That measurement was right
about what it measured and wrong as a conclusion — what lost was the
`mpz` layer, not the algorithm.

### The fixture that could not see the subtraction

Worth recording, because it took two attempts and an adversarial review
to get right. REDC ends in a conditional subtraction, and whether a test
can SEE it depends not on how often it fires but on how far `n²` sits
below the limb boundary. Two bits of slack are enough to make the
recurrence without the subtraction a fixed point: every value the test
observes is canonical anyway. Both earlier fixtures sat there, and
deleting the subtraction entirely left the suite green — while the
docstring blamed frequency, which was the wrong cause.

Real keys are flush against that boundary about one time in seven, and
there the missing subtraction overflows the buffer and corrupts
ciphertexts. The fixture set now runs every test over three shapes,
including the production one, and asserts the invariant the subtraction
exists to establish — that `mul` returns a value below the modulus.

### The repository is in English

Sources, tests, documentation and package metadata. The short
description shown on the PyPI page was still Russian in 0.3.0; it is a
property of the published metadata and could only be corrected by a
release.

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
