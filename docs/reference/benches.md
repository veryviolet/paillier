# Benchmarks

`benches/` holds benchmarks, not tests: they are run by hand, assert
nothing, and print numbers. Each answers **its own** question — one the
others do not answer.

There used to be eight of them, each measuring its own piece with its
own sample by its own method. They could not be compared with one
another, and two numbers rotted on exactly that: "85 µs in `add_many`"
and "4.87 s key generation".

## `measure.py` — every operation at once

```bash
python benches/measure.py
```

One dataset, one order of operations, one repeat count, one output
format for any library: encryption serially and in a batch, addition,
decryption, key generation, ciphertext lengths, and accuracy on
symmetric and on non-negative input.

**Median and spread everywhere**, not best time. Best-of-N estimates a
lower bound, not typical behaviour, and comparing it against another
quantity's median is invalid. The spread between runs of identical code
was measured at about 7 %: any effect smaller than that is not measured
by a single run at all.

The accuracy reference is the exact sum of the **original** numbers in
`Fraction`. The sum of rounded values equals the scheme's result by
construction: comparing against it measures homomorphism, which is
exact, not the encoding error.

## `acc_rounding.py` — does the encoder round or truncate

A discriminating observation: a value whose scaled magnitude has
fractional part 0.7. Truncation drops it, rounding adds one.

Fractional part 0.7 rather than 0.5 on purpose: `1.0000005` is not
exactly representable in binary `f64`, and a tie probe would turn into a
probe of which way the representation error fell.

## `modmul.rs` — the cost of a modular multiplication

```bash
cargo bench --bench modmul
```

Plain `a·b mod n²` against Montgomery form **on top of `rug::Integer`**,
plus the cost of parsing bytes into a number and an exact copy of the
`add_many` loop.

This is where the record lives of why Montgomery was rejected at that
level: it is assembled from full-width operations with an allocation at
every step, and loses by a factor of 1.19.

## `secure_pow.rs` — the cost of `mpz_powm_sec`

```bash
cargo bench --bench secure_pow
```

At the same lengths as the CRT components. The ratio is stable —
1.54–1.55 at 2048 bits — while the absolute values wander by a few
percent between runs.

## `window_select.rs` — the cost of constant-time reading

```bash
cargo bench --bench window_select
```

Two table layouts side by side, on the same `hs`, `n²` and exponent,
with an equality check on the results inside the benchmark itself:
entry selection by index against selection by mask.

The row count comes from **the same function** the production path uses.
It used to hold the formula for a four-bit window, and the benchmark
built a table one and a half times larger than production — publishing a
cost measured on a structure the library never builds.

## `exponent_length.rs` — what a shorter exponent would buy

```bash
cargo bench --bench exponent_length
```

`pow_by_table` timing at 1024, 512 and 256 exponent bits. Total
encryption time follows by adding the constant part, which `measure.py`
measures.

!!! warning "These numbers are DERIVED by subtraction"

    The exponent length is not configurable from outside — it follows
    rigidly from the modulus length. And the constant part is the
    difference of two independently measured quantities of about 1030 µs
    each, so its own uncertainty is comparable to itself.
