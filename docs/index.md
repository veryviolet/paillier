# paillier

Additively homomorphic Paillier encryption: a Rust implementation on top
of GMP, bound to Python through pyo3.

Homomorphic means encrypted numbers can be added without decrypting
them:

```python
import paillier

pub, sec = paillier.generate_keypair(2048)

blobs = [bytes(b) for b in paillier.encrypt_many(pub, [1.5, 2.25, -0.75])]
total = paillier.add_many(pub, blobs)      # adding CIPHERTEXTS

paillier.decrypt(sec, total)               # 3.0
```

Whoever does the adding never sees the terms. Whoever holds the private
key sees only the sum. That is the whole point of the scheme.

## What you need to know before using it

!!! warning "This is not textbook Paillier"

    The scheme is the **Damgård–Jurik variant with a short exponent**:

    ```
    c = (1 + m·n) · hs^r mod n²,   hs = h^n,  h = −x² mod n,  |r| = |n|/2
    ```

    instead of the textbook `c = g^m · r^n mod n²`. The consequence:
    ciphertext indistinguishability rests on **more than DCRA alone** —
    it needs an additional short-exponent assumption. That assumption is
    standard and published, but it exists, and "secure under DCRA" is
    not a sentence you can say here unconditionally.

    Details: [The scheme](concepts/scheme.md),
    [Short-exponent security](short-exponent-security.md).

!!! warning "There is NO constant time"

    Two timing side channels are closed, one stays open — about
    **0.118 bits** out of 1024. It is named, measured, and guarded by a
    test that watches it does not grow. Details:
    [Timing side channels](concepts/timing.md).

## Numbers

2048-bit key, one machine, medians over five repeats:

| operation | cost |
|---|---|
| encryption, all cores | **6500+ ops/s** |
| encryption, one core | 980 ops/s |
| addition | 7.3 µs per term |
| decryption | 3.75 ms |
| key generation | 1.4–2.8 s (spread 1.0–10.3) |
| ciphertext | 512–513 B |

Encryption is 98 % modular multiplications inside the window table;
encoding, serialisation and everything else come to under half a percent
together. Key generation has an enormous spread because it is a search:
safe primes are rare and the time to a hit is random — a single
measurement there means nothing.

All of it reproduces from the repository: `python benches/measure.py`.
What each benchmark answers and what it deliberately does not:
[Benchmarks](reference/benches.md).

## What it does that a textbook implementation does not

* **the key is validated** — ours when generated, a peer's when
  accepted. Skipping validation of a private key is a compile error, not
  an oversight;
* **`hs` is derived from `n` in place**, never imported, so the
  encrypting side never has to trust a foreign number it cannot verify
  by any computation;
* **rounding to nearest, not truncation** — on sign-constant data
  truncation gives an error that grows linearly with the number of
  terms rather than as `√k`;
* **refusals instead of plausible numbers** — `NaN`, infinities, an
  empty sum, a mixed-scale batch, an over-long modulus from a peer.

## Installation

```bash
pip install pypaillier
```

Wheels are built for CPython 3.10, 3.11, 3.12 and 3.13. Details:
[Installation](getting-started/installation.md).

## Legal

Licence texts, where the techniques came from, and how the LGPL §4
conditions are met:
[`NOTICE.md`](https://github.com/veryviolet/paillier/blob/main/NOTICE.md).
