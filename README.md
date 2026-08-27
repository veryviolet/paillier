# pypaillier

**Additively homomorphic Paillier encryption: a Rust implementation on
top of GMP, bound to Python through pyo3.**

Add encrypted numbers without decrypting them:

```python
import paillier

pub, sec = paillier.generate_keypair(2048)

blobs = [bytes(b) for b in paillier.encrypt_many(pub, [1.5, 2.25, -0.75])]
total = paillier.add_many(pub, blobs)      # adding CIPHERTEXTS

paillier.decrypt(sec, total)               # 3.0
```

Whoever does the adding never sees the terms. Whoever holds the private
key sees only the sum.

```bash
pip install pypaillier
```

Wheels for CPython 3.10–3.13, `manylinux_2_17`. No compiler and no
system GMP required. The distribution is `pypaillier`; the import name
is `paillier`.

📖 **[Documentation](https://veryviolet.github.io/paillier/)**

## Before you use it

**This is not textbook Paillier.** The scheme is the Damgård–Jurik
variant with a short exponent, `c = (1 + m·n) · hs^r mod n²`. Ciphertext
indistinguishability therefore rests on an additional short-exponent
assumption, not on DCRA alone.

**Constant time is not claimed as a whole-library property.** The three
timing channels found in encryption are closed: two are guarded by tests
that measure a slope against the secret, and the third — the cache
address — cannot be, because it changes neither the answer nor the time
measurably; it is guarded by a check on the shape of the code. Key
generation is a prime search and is not constant time at all.

Both are explained in full, with the measurements, in the
[documentation](https://veryviolet.github.io/paillier/).

## Numbers

2048-bit key, medians:

| operation | cost |
|---|---|
| encryption, all cores | 6800+ ops/s |
| encryption, one core | 1066 ops/s |
| addition | 7.1 µs per term |
| decryption | 3.9 ms |
| key generation | 2.2–3.3 s |
| ciphertext | 512–513 B |

Reproduce with `python benches/measure.py`.

## Accuracy

Fixed point, rounding to nearest. The scale is configurable and travels
inside the ciphertext, so decryption reads it from there and addition
refuses a batch that mixes scales:

```python
blobs = paillier.encrypt_many(pub, values, scale_pow10=12)
```

The default is `10^8`. See
[Encoding and scale](https://veryviolet.github.io/paillier/concepts/encoding/).

## Building from source

```bash
pip install maturin
maturin build --release
```

Needs stable Rust. GMP is built and linked statically.

## Licences

**The sources** are MIT OR Apache-2.0, at your option.

**The built wheels** additionally contain GMP, statically linked through
[`rug`](https://gitlab.com/tspiteri/rug), and therefore fall under
**LGPL-3.0+** as a whole. For a binary with no LGPL code inside, build
from the source distribution against your own GMP:
`pip install --no-binary pypaillier pypaillier`.

Full breakdown, including how the LGPL §4 conditions are met:
[`NOTICE.md`](NOTICE.md).
