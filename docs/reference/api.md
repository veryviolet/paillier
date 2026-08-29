# API

The `paillier` module. Everything it exposes is listed here.

## `generate_keypair(bits=3072)`

Returns `(PublicKey, SecretKey)`.

Generates two **safe** primes of `bits/2` each and validates the
resulting key. Keys shorter than 2048 bits are not generated: NIST
SP 800-57 requires that length for 112-bit security.

It costs seconds and has a **huge spread** — anywhere from 1 to 10
seconds at 2048 bits on the same machine. It is a search: safe primes
are rare, and the time to a hit is random.

```python
pub, sec = paillier.generate_keypair(2048)
```

## `PublicKey`

### `PublicKey.from_n(raw)`

Builds a public key from **the modulus alone** — the thing that came
over the wire. `hs` is derived right here, from `n`, rather than
accepted from outside.

It costs about 0.03 s at 3072 bits, because the table of powers is built
along with the key. Do this **once per session**.

Refuses an even modulus, one that is too short, and one that is too
long. The length is cut off by raw byte count **before any arithmetic**:
the modulus arrives from a peer, and 64 megabytes instead of a key must
not cost the process anything.

### `modulus_bytes()`

The modulus in bytes, most significant first. The only thing that
travels to a peer.

### `exponent_bits`

The length of the random exponent in bits — half the modulus length.
Exposed so it can be checked **by number** rather than by guesswork.

### `plaintext_bound_bits`

The largest accepted plaintext in magnitude, in bits: `n/2`, shrunk to
reserve headroom for a sum.

## `encrypt_many(pub, values, scale_pow10=8)`

Encrypts a list of numbers, returns a list of blobs.

Runs **across all cores**. Encrypting one at a time in a Python loop
throws away a factor of six.

`scale_pow10` is the power-of-ten exponent, from 0 to 18. It travels in
every blob as the first byte. See
[Encoding](../concepts/encoding.md).

Refuses `NaN`, infinities, numbers that overflow `f64` once scaled, and
numbers outside the key's admissible range.

## `add_many(pub, blobs)`

Adds ciphertexts, returns a single blob.

Refuses: an empty batch; a batch longer than `2^20`; a ciphertext
outside `[1, n²)`; a batch that **mixes scales**.

!!! note "The `2^20` cap is not a guarantee"

    It is per call, and the result can be fed into a second call. What
    actually keeps sums in the group is the gap between the key floor
    (`2^2026`) and what is encodable from `f64` at all (about `2^1024`):
    a thousand bits short of overflow.

## `multiply_many(pub, blobs, scalars, *, scalar_scale_pow10=None)`

Multiplies each ciphertext by a **known** scalar — `E(x) → E(k·x)` — and
returns a list of blobs, paired with the input by position.

The scale of a product is the **sum** of the two scales, and the header
of the returned blob says so, so `decrypt` divides by the right thing
without being told. `scalar_scale_pow10` defaults to the scale of the
ciphertext, so the ordinary case is `8 + 8 = 16`.

Refuses: a length mismatch between `blobs` and `scalars`; a scalar that
is `NaN` or infinite; a scalar that **encodes to zero**; a scalar past
the fixed exponent width; a product scale above `1e18`; a ciphertext
outside `[1, n²)` or not invertible.

!!! warning "Multiplication does not compose at the default"

    A second multiplication would be `16 + 16 = 32` — refused. Chaining
    means lowering `scalar_scale_pow10` on both calls.

    For the same reason a product cannot be added to an ordinary
    ciphertext: `add_many` refuses a mixed batch. Encrypt the companions
    at the product's scale — `encrypt_many(pub, values, scale_pow10=16)`.

!!! note "A scalar that encodes to zero is refused, an exact zero included"

    `E(x)^0` is the constant `1`: the value is destroyed and the result
    becomes a two-byte blob anyone can recognise. Where the scalar is a
    share or a weight, a vanishing one means "this bucket is empty", and
    publishing that as a distinctive blob is a leak rather than a result.
    Encrypt a zero if a zero is what is wanted.

!!! info "The exponent runs at a FIXED width"

    The scalar is usually the caller's own secret, so this takes the
    secret-exponent path, as decryption does. That hides the exponent's
    value but not its length — and its length is the magnitude of the
    scalar. So the exponent is offset to a constant width and the offset
    divided out afterwards, at the cost of a second exponentiation.

    The consequence is the refusal above: a scalar that does not fit the
    fixed width is rejected rather than run at a wider exponent. At the
    default scale that admits `|k| ≤ 1.8e11`.

    The sign is hidden too, and by construction rather than by care: the
    offset makes every exponent positive, so both exponentiations and the
    inversion run unconditionally. There is no branch on the sign to
    observe.

    An earlier draft of this page claimed the opposite — that a negative
    scalar costs an inversion and a positive one does not. That described
    a naive implementation, not this one, and it was caught by review
    rather than by a test.

!!! danger "Do NOT transmit a raw product if the scalar is secret"

    The output is `E(x)^k` and nothing else — a deterministic function of
    the input ciphertext and the scalar. Anyone who sees BOTH the input
    and the output recovers `k` by trying candidates: `n` is public, so
    each guess costs one exponentiation, and a scalar that is a share or
    a small weight has few candidates worth trying.

    Which means the fixed-width construction above protects a side door
    while this one stands open. It is worth having — timing is available
    to a neighbour on the same machine, who may never see the
    ciphertexts — but it is not what keeps `k` secret from someone
    watching the wire.

    Use [`rerandomize`](#rerandomizepub-blobs) before transmitting, or
    sum the products with something the other side did not send. The
    analytics exchange this feature was built for does the latter, which
    is why the library does not do it for you: it cannot know which of
    your ciphertexts are about to leave.

## `multiply_many_public(pub, blobs, scalars, *, scalar_scale_pow10=None)`

The same product as
[`multiply_many`](#multiply_manypub-blobs-scalars-scalar_scale_pow10none),
computed for a caller who states that the scalar is **not** a secret.

Byte-for-byte identical results. The same refusals, plus one of its own.
About twelve times faster, and one property fewer.

### Which one to reach for

`multiply_many` keeps the exponent's width constant, at the cost of two
exponentiations and a modular inversion per product. That is right when
the scalar is what the exchange conceals — an analytics bucket share,
say.

This one runs a single windowed exponentiation. Reach for it when the
scalar is the multiplying party's own data, never leaves it, and neither
do the products. Vertical linear training is the case it was added for:
the passive party multiplies encrypted residuals by its own features and
sends only their masked sum.

### What is traded, measured

The time depends on the scalar's magnitude. On a 2048-bit key:

| exponent | this function | `multiply_many` |
|---|---|---|
| 1 bit | 0.0046 ms | ~2.1 ms |
| 64 bits | 0.3200 ms | ~2.2 ms |

One observation separates a small scalar from a large one at about 93%
accuracy; twenty-seven reach 99%. If the party receiving the answer must
not learn the magnitudes, this is the wrong function — and that party is
usually the one being defended against, so the question is worth asking
rather than assuming.

Typical shape, batches of 200 at ~29-bit exponents: **0.181 ms against
2.193 ms, a factor of 12.1**.

### Bounds

`|k| < 2^53` after encoding, and **this range is narrower than
[`multiply_many`](#multiply_manypub-blobs-scalars-scalar_scale_pow10none)'s,
not wider.** That function refuses an encoded `|k| ≥ 2^64`; 2^53 is below
2^64 at every scale. Measured across 3000 combinations of scale and
magnitude: 108 inputs this path refuses and the other accepts, none the
other way round.

The two bounds differ in kind. `2^64` was a timing requirement — every
exponent had to be the same width. `2^53` is where an `f64` stops holding
every integer, so past it the value multiplied in is not the value you
named: `10^20` arrives as `1.9999999999999997e20`. `multiply_many` rounds
there silently; this refuses.

At the default scale of 1e8 that means `|k| ≤ 9.0e7`. A unix timestamp
(1.7e9), a population count, a revenue figure — all accepted by
`multiply_many`, all refused here. The way through is a lower
`scalar_scale_pow10`, trading fractional precision for range: at 1e2 the
ceiling is 9.0e13.

The plaintext space (2^2027 at a 2048-bit key) never binds either way,
and nothing wraps silently: every out-of-range path ends in a refusal.

### Refusals

Everything `multiply_many` refuses, plus:

*   **a ciphertext sharing a factor with `n` — for every scalar.**
    `pow_mod` reports this only when the exponent is negative, because
    only then does it need the inverse. Left to it, the same input was
    accepted on positive scalars and rejected on negative ones. The check
    is explicit here.

## `rerandomize(pub, blobs)`

Same plaintext, different bytes. Each ciphertext is multiplied by a fresh
encryption of zero.

Runs across all cores. Costs about one **encryption** per ciphertext,
because that is what it is: one exponentiation at the full exponent
length.

Refuses an empty blob, an unknown scale exponent, and a ciphertext
outside `[1, n²)`. The scale byte passes through unchanged.

!!! info "Why this is a separate call and not a flag"

    The homomorphic operations are deterministic: `add_many` of the same
    terms gives the same bytes, a one-term sum gives its input back
    verbatim, `multiply_many` gives exactly `E(x)^k`. Whoever knows the
    inputs can confirm a guess about the operation by recomputing it.

    That only matters when the result LEAVES. Inside a computation the
    property buys nothing and costs an encryption apiece — so it is the
    caller who applies it, at the point where they know what is being
    sent, which the library cannot know.

    A flag was considered. On by default it charges every caller for
    something most do not need; off by default it is left off exactly
    where it costs most.

!!! warning "It hides WHICH ciphertext, not the value"

    Re-randomising does nothing against a party that can decrypt. If the
    recipient of your result holds the private key, they read the
    plaintext, and this changes nothing about that.

## `decrypt(sec, blob)`

Returns a `float`. The scale is taken from the blob itself.

Refuses an empty blob, an unknown scale exponent, and a value that is
not a ciphertext under this key.

!!! warning "There is no 'this ciphertext under this key' check"

    Nor can there be: it does not follow from `n` alone. A ciphertext
    made under a different key will usually lead to a refusal — but not
    always.

## `__version__`

The package version, taken from `Cargo.toml` at build time rather than
typed in a second place.

## Blob format

```
[1 byte: scale exponent] [ciphertext, most significant byte first]
```

The ciphertext is written at **minimal** length, not padded to a fixed
width: measured `{512: 2, 513: 398}` over four hundred encryptions with
a 2048-bit key. You cannot slice the buffer at a constant stride.
