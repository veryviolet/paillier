# First run

## The key

```python
import paillier

pub, sec = paillier.generate_keypair(2048)
```

This generates **safe primes** — `p = 2p′ + 1` with `p′` prime as well.
That costs more than Blum primes (seconds against a fraction of one),
and it buys the non-smoothness of `ord(hs)` **by construction** rather
than statistically. Details: [The scheme](../concepts/scheme.md).

Keys shorter than 2048 bits are not generated at all: NIST SP 800-57
requires that length for 112-bit security, and anything shorter is not
cryptography.

## Encrypt, add, decrypt

```python
values = [1.5, 2.25, -0.75]

blobs = [bytes(b) for b in paillier.encrypt_many(pub, values)]
total = paillier.add_many(pub, blobs)

paillier.decrypt(sec, total)   # 3.0
```

`encrypt_many` encrypts **in a batch and across all cores**: on this
machine 6855 items per second against 1066 on one. Encrypting one at a
time in a Python loop throws that factor away.

`add_many` also takes a batch: one call into Rust for the whole thousand
terms instead of a thousand calls.

## Encrypting under someone else's key

A party that only encrypts needs no private key — and no parameter at
all beyond the modulus:

```python
wire = bytes(pub.modulus_bytes())      # everything that goes over the wire

peer = paillier.PublicKey.from_n(wire)
blobs = [bytes(b) for b in paillier.encrypt_many(peer, [7.0, 8.0])]
```

`from_n` derives `hs` **itself**, from `n` alone. Importing it would
have been simpler, but then the encrypting side would have to trust a
foreign number that cannot be verified by computation at any price.

Building a peer key costs about 0.03 s at 3072 bits, so do it **once per
session**, not once per message: the table of precomputed powers — the
whole reason the scheme is fast — is built along with the key.

## Scale

The default is `10^8`. If your data is sign-constant and the sums are
long — bucket counters, squared gradients — pick a larger one:

```python
blobs = paillier.encrypt_many(pub, values, scale_pow10=12)
```

The scale travels **inside the ciphertext**, so decryption reads it from
there and `add_many` refuses a batch that mixes scales. The two sides
have nothing to agree on. Details:
[Encoding and scale](../concepts/encoding.md).

## What not to do

```python
paillier.add_many(pub, blobs_from_another_key)   # silently ruins the sum
```

There is no "this ciphertext was made under this key" check, and there
cannot be one: it does not follow from `n` alone. The refusal arrives
later, at the key holder, with no address on it. Keep a batch under one
key.
