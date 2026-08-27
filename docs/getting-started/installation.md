# Installation

```bash
pip install pypaillier
```

The distribution is `pypaillier`; the import name is `paillier`. PyPI
would not take `paillier` as a project name, and there was no reason to
carry that into the API — every example in this documentation says
`import paillier`.

## What actually gets installed

A compiled Rust extension. No compiler and no system GMP are required:
GMP is built and linked statically into the wheel when the package is
built.

Wheels are built **separately for each** CPython version — 3.10, 3.11,
3.12 and 3.13 — and that is a deliberate refusal of `abi3`.

!!! note "Why not `abi3`"

    One wheel for every version looks more convenient than four. But a
    compatibility tag you cannot trust is worse than no tag at all, and
    the failure mode is real: an extension tagged `abi3` while actually
    using an unstable symbol installs perfectly and then dies on import
    on the first interpreter that removed the symbol.

    A per-version wheel cannot lie about compatibility: either it was
    built for this interpreter or it does not exist.

The platform tag is `manylinux_2_17` (also known as `manylinux2014`),
the glibc floor that installs on essentially any live Linux.

## Building from source

You need stable Rust and `maturin`:

```bash
pip install maturin
maturin build --release
pip install target/wheels/paillier-*.whl
```

Or straight into the current environment, with no intermediate wheel:

```bash
maturin develop --release
```

!!! warning "Do not build without `--release`"

    In a debug build, safe-prime generation takes minutes instead of
    seconds, and the constant-time measurements mean nothing at all.

## Verifying

```python
import paillier
paillier.__version__
```

The version comes from `Cargo.toml` **at build time** rather than being
typed in a second place: two copies of a number drift apart silently,
and a drifted version lies about which code is installed.
