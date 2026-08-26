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
