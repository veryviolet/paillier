# Third-party notice

## In short

**The sources of this package** — `src/`, `tests/`, `benches/`, `docs/`
— are distributed under **MIT OR Apache-2.0**, at your option.

**The built wheels** additionally contain GMP, linked statically through
`rug`, and therefore fall under **LGPL-3.0+** as a whole. Installing a
wheel from PyPI gets you a combined work, not only our code.

If that does not suit you, build from the source distribution against
your own GMP: `pip install --no-binary pypaillier pypaillier`.

## LGPL: `rug`, `gmp-mpfr-sys`, GMP

| component | licence |
|---|---|
| [`rug`](https://gitlab.com/tspiteri/rug) 1.30 | LGPL-3.0+ |
| [`gmp-mpfr-sys`](https://gitlab.com/tspiteri/gmp-mpfr-sys) 1.7 | LGPL-3.0+ |
| [GNU MP](https://gmplib.org/) | LGPL-3.0+ (or GPL-2.0+) |

Texts are included: [`LICENSE-LGPL`](LICENSE-LGPL) and
[`LICENSE-GPL`](LICENSE-GPL) — the LGPL incorporates the GPL terms by
reference, so both are needed.

`gmp-mpfr-sys` is a **direct** dependency, not only one inherited
through `rug`. `src/mont.rs` calls four of its `mpn_*` functions to keep
the encryption arithmetic on fixed-width limb buffers, which is what
closes the leading-zeros timing channel. Cargo resolves it to the same
version `rug` requires, so the wheel contains one GMP and not two.

### `unsafe`, and whose responsibility it is

This crate carries `#![deny(unsafe_code)]`, lifted in exactly one file,
`src/mont.rs`, which states in its own header what each `unsafe` block
does and what contract it upholds.

Worth being plain about what that means. Before, all of the unsafe
arithmetic was `rug`'s and `gmp-mpfr-sys`'s — roughly a thousand blocks
across the two, over a GMP built from 1500-odd C files. That has not gone
anywhere. What changed is that about 150 lines of REDC and buffer
handling moved from their responsibility to ours.

So the defensible statement is "there is no `unsafe` outside one audited
module of this crate", which the compiler checks. The statement "a
library without unsafe code" was never true of the built wheel and is not
claimed anywhere.

### How the LGPL §4 conditions are met

The wheel is a "Combined Work" in the sense of §4: our code is linked
with the library statically. The conditions are met as follows.

**§4(a), notice.** This file, also named in `README.md` and in the
documentation.

**§4(b), copies of the licences.** `LICENSE-LGPL` and `LICENSE-GPL` are
in the repository, in the source distribution, and inside the wheel
(`pypaillier-*.dist-info/licenses/`).

**§4(d), ability to relink.** Option **d)(0)** is taken: everything
needed to recombine our code with a DIFFERENT version of the library is
provided.

* our sources are fully open:
  <https://github.com/veryviolet/paillier>;
* the same code ships in the source distribution on PyPI
  (`pypaillier-X.Y.Z.tar.gz`);
* the build reproduces with one command (`maturin build --release`), and
  the `rug` version is not pinned exactly — `Cargo.toml` declares
  `rug = "1.24"`, i.e. semver-compatible, and it can be replaced with
  your own, including a modified one.

We neither pin an exact GMP version nor patch it: `gmp-mpfr-sys` builds
a stock GMP release.

### Avoiding LGPL code in the binary

`gmp-mpfr-sys` can link against a system GMP instead of building it
statically. We do not do that: a `manylinux` wheel cannot rely on GMP
being installed system-wide, and a package that will not install without
a prior `apt install` is a bad package. If you need a binary with no
LGPL code inside, build one yourself with the appropriate flags.

## MIT / Apache-2.0

| component | role | licence |
|---|---|---|
| [`pyo3`](https://github.com/PyO3/pyo3) | Python binding | MIT OR Apache-2.0 |
| [`rand`](https://github.com/rust-random/rand) | random generator | MIT OR Apache-2.0 |
| [`rayon`](https://github.com/rayon-rs/rayon) | parallel encryption | MIT OR Apache-2.0 |
| [`fast-paillier`](https://github.com/LFDT-Lockness/fast-paillier) | **test oracle only** | MIT OR Apache-2.0 |

### `fast-paillier`

This package began as a binding on top of that crate, and that is worth
stating plainly. It is now **not part of the library build**: it is
declared in `dev-dependencies` and used by a single test,
`tests/decrypt_matches_crate.rs`, as an independent decryption oracle —
an implementation checked against itself proves nothing.

Our code is not a derivative work. Verified by a line-by-line comparison
of the sources: **not a single shared line** of code longer than 25
characters. In the built wheel there is none of their code — no symbols,
no paths.

The scheme variant implemented here — Damgård–Jurik with a short
exponent — is published in the academic literature and belongs to the
field.
