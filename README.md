# paillier

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

Wheels for CPython 3.10, 3.11, 3.12 and 3.13. No compiler and no system
GMP required.

The distribution is `pypaillier`; the import name is `paillier`. PyPI
would not take `paillier` as a project name, and there was no reason to
carry that into the API.

📖 **[Documentation](https://veryviolet.github.io/paillier/)**

## Read this before using it

**This is not textbook Paillier.** The scheme is the Damgård–Jurik
variant with a short exponent: `c = (1 + m·n) · hs^r mod n²`, where the
base is fixed and the exponent — `|n|/2` bits — is what varies. Almost
all of the speed comes from that, and so does the consequence:
ciphertext indistinguishability rests on **more than DCRA alone**. It
needs an additional short-exponent assumption. That assumption is
standard and published, but it exists, and "secure under DCRA" is not a
sentence you can say here unconditionally.

**There is NO constant time.** Two timing side channels are closed, one
stays open — about **0.118 bits** out of 1024. It is named, measured,
and guarded by a test that watches it does not grow.

Both statements are worked through in full, with measurements and with
what the scheme does *not*
give: [documentation](https://veryviolet.github.io/paillier/).

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
encoding, serialisation and the rest come to under half a percent
together. Key generation has an enormous spread because it is a search:
safe primes are rare and the time to a hit is random.

Everything here is reproducible from the repository:
`python benches/measure.py`.

## Accuracy is configurable

```python
blobs = paillier.encrypt_many(pub, values, scale_pow10=12)
```

The scale travels **inside the ciphertext**: decryption reads it from
there, and addition refuses a batch that mixes scales. The two sides
have nothing to agree on.

At `scale_pow10 = 12` the sum error over a million sign-constant terms
drops below the resolution of `f64` itself — at the cost of narrowing
the input range from `|v| ≲ 9e7` to `≲ 9e3`.

## Checks

```bash
cargo test --release
python -m pytest
```

Performance and accuracy benchmarks live in `benches/`, each answering
one question:
[reference](https://veryviolet.github.io/paillier/reference/benches/).

## Building from source

```bash
pip install maturin
maturin build --release
```

Needs stable Rust. GMP is built and linked statically; you do not need
to install it separately.

## Licences

**The sources** are MIT OR Apache-2.0, at your option.

**The built wheels** additionally contain GMP, statically linked through
[`rug`](https://gitlab.com/tspiteri/rug), and therefore fall under
**LGPL-3.0+** as a whole. Installing a wheel from PyPI gets you a
combined work, not only our code.

If you need a binary with no LGPL code inside, build it from the source
distribution against your own GMP:
`pip install --no-binary pypaillier pypaillier`.

Full breakdown, including how the LGPL §4 conditions are met and where
the techniques came from:
[`NOTICE.md`](NOTICE.md).
