# Timing side channels

**Three channels in encryption are closed, named and measured. Constant
time is still not claimed as a property of the whole library** — the
difference between "the channels we found are closed" and "there are no
channels" is exactly the difference this page is written about.

## What "constant time" even means

Not "the same number of microseconds" — timing wanders with machine load
regardless. The requirement is different: **changing the secret must not
change observable behaviour**.

The secret here is the exponent `r`, fresh for every message. An observer
who learns `r` recovers the plaintext outright: compute `hs^r` (base and
modulus are public), divide the ciphertext by it, get `1 + m·n`, subtract
one, divide by `n`.

The observer is not a person with a stopwatch on the network — it is a
**process on the same machine**, sharing the CPU cache with us.

## Exponent-weight channel — CLOSED

The first version of the table skipped zero digits: a zero window meant
no multiplication. Time was then directly proportional to the number of
non-zero digits of `r`. Measured: from 0.2 µs on an empty exponent to
1576 on a full one, linear, at 6.1 µs per digit.

Closed by multiplying **at every window**, without exception.

!!! note "The padding that used to be needed, and why it is gone"

    The zero entry held `n² + 1` rather than `1`. One is a single-limb
    number: GMP computed `result · 1` in one pass and the following
    `% n²` returned immediately, so a zero window was nearly free again.

    How that was caught: I substituted one and expected a slowdown of one
    sixteenth. The measurement showed 0.6 % instead of 6.7 %, and I read
    that as good news — though the missing six percent *were* the work
    that was not being done.

    **Cheaper than expected is not a gift. It is a signal.**

    The padding is no longer there, and not because the problem went
    away. The arithmetic now runs on fixed-width limb buffers, where no
    value is cheaper to multiply by than another — see below.

Guarded by `tests/timing_channel.rs`. The criterion is the **slope** of
time against weight, not absolute time: absolute time depends on the
machine, slope does not.

## Cache channel — CLOSED

A table entry used to be fetched by an index equal to the secret digit.
The operation itself does not branch, but the **memory address depends on
the secret**, and a neighbour sharing the cache sees which line we pulled
in.

Now the whole row is read and the wanted entry is selected with an
arithmetic mask, with no branch anywhere. The sequence of addresses is
identical for any exponent.

The cost of that was measured and turned out not to be what I had
assumed. The code said "closing it would mean paying sixteen times over"
— a figure inflated by more than an order of magnitude: measured
**1–5 %**, invisible in an end-to-end run.

That 1–5 % is a historical figure, taken when both arms of the benchmark
were `mpz` and only the selection differed. `benches/window_select.rs`
no longer isolates it — its second arm now also uses Montgomery form, so
it prints the whole difference between the two states of the library.

!!! warning "This channel cannot be guarded by measurement"

    And for a while the documentation claimed it was, next to the other
    two. It is not the same kind of thing. Reading one entry and reading
    all sixty-four give identical output, and the difference in cost —
    that same 1–5 % — is inside the run-to-run noise of the slope tests.
    An adversarial review reverted the selection to the address-dependent
    form and every test in the repository stayed green.

    What guards it now is `tests/constant_time_shape.py`: a check that
    `select_entry` never derives an address from the secret digit and
    always traverses the whole row. It is a source-level tripwire on the
    exact regression, not a proof — renaming the parameter evades it.
    Said plainly because the alternative was a claim that could not be
    cashed.

!!! note "Laid out in limbs, not bytes"

    Byte-wise constant-time reading cost +26 %; limb-wise, a few percent.
    The price is bounded by the number of iterations, not by the volume of
    data.

## Leading-zeros channel — CLOSED

This one was open for a long time, and the record of it is worth keeping.

The loop starts from one, and while the low digits of `r` were zero the
accumulator stayed a single-limb `Integer`, making those multiplications
cheaper. Measured: **−6.3 µs per leading zero**, at fixed weight.

The obvious cure does not work, and it was tried: starting from `n² + 1`
gave −6.56, because `%` returns the canonical residue and after the first
reduction the accumulator is one again. **While a value is congruent to
one, GMP represents it as one.**

What closes it is not a different value but a different container. The
accumulator and the whole table now live in **fixed-width limb buffers**
(`mpn_*` rather than `mpz_*`): a product of two `k`-limb buffers costs
the same whether the operands are `n²−1` or one, because nothing looks at
how many leading zeros there are. Reduction modulo `n²` would ordinarily
need a division, which *is* value-dependent — so the arithmetic is in
**Montgomery form**, which replaces the division with a multiplication
and one branch-free conditional subtraction.

Measured after the change: **−0.2 µs per leading zero**, thirty-one times
smaller and indistinguishable from the residual slope of the
already-closed weight channel. Over eight runs the residual wanders
between −0.98 and +0.65 and changes sign, which is what noise looks like.

!!! info "The size of what used to leak"

    The run of leading zeros is geometric, a digit is zero with
    probability `q = 2^−w`, and the entropy is

    ```
    H = [−(1−q)·lg(1−q) − q·lg q] / (1−q)
    ```

    At `w = 6` that is 0.118 bits out of 1024; at `w = 4` the same
    formula gives 0.36. Against a `2^512` margin it was never a break —
    but "does not breach the margin" and "is closed" are different
    statements.

!!! warning "The price: this crate is no longer free of `unsafe`"

    `mpn_*` is a C API, so calling it needs `unsafe`. It is confined to
    one module, `src/mont.rs`, which is the only place the crate-wide
    `#![deny(unsafe_code)]` is lifted — four GMP calls over buffers whose
    lengths are checked in safe Rust immediately before each call. What
    changed is whose responsibility that arithmetic is: it used to be
    `rug`'s, and now 150 lines of it are ours.

Guarded by `tests/timing_channel.rs::time_does_not_depend_on_leading_zeros`
— now for absence, not for the leak "not growing". The threshold was
deliberately tightened from 15.0 to 2.5 µs per zero: at 15.0 the test
stayed green under a mutation that reintroduced a branch on the secret
digit and drove the slope to −4.58.

## Decryption

There the secret is different, and worse: the exponent derives from `λ`,
the long-lived secret of the key. A leak during encryption costs
fractions of a bit about a one-shot `r`; a leak during decryption
accumulates over every decryption for the whole life of the key.

That is why exponentiation goes through `mpz_powm_sec` rather than
`mpz_powm`: GMP's documentation requires exactly this for secret
exponents. It costs a factor of 1.55, and it is the only place where we
pay for security in a big way.

## What is still NOT claimed

Three closed channels are not a proof of constant time, and this page
does not present them as one.

* **`multiply_many_public` is variable time BY CONSTRUCTION**, and that
  is the point of it. Everything else on this page is a channel that was
  closed; this one is a channel sold deliberately, for a factor of
  twelve. Its exponent is the scalar itself, so the running time follows
  the scalar's bit length: 0.0046 ms at one bit against 0.3200 ms at
  sixty-four. One observation tells a small scalar from a large one about
  93% of the time; twenty-seven give 99%.

  It exists because a caller can know the scalar is not a secret —
  vertical linear training multiplies by the multiplying party's own
  features, which never leave it. `multiply_many` stays flat and stays
  the answer whenever the question is unclear. If you are reading this
  page to learn whether the timing is constant: for that one function it
  is not, and nothing else here makes it so.
* **Key generation is not constant time** and is not meant to be. It is a
  search for safe primes: the time to a hit is random and depends on the
  primes found, which is why the measured spread is 0.4–10.3 s.
* **GMP does not promise data-independence** for `mpn_mul_n` and
  `mpn_addmul_1`. They branch on SIZE, and our sizes are fixed for the
  life of a key — but that is an argument from how they are implemented,
  not a guarantee from their documentation. GMP's own explicitly
  constant-time primitive, `mpn_sec_mul`, is deliberately not used: to
  stay constant-time it forgoes sub-quadratic multiplication, which at 64
  limbs costs more than everything gained here.
* **Only the channels that were looked for have been measured.** Three
  were found and closed; a fourth would be found the same way, by
  measuring a slope.

## Nothing is claimed about other implementations

Whether any other Paillier library is constant-time is not asserted here
either way. **Absence of a stated guarantee is not proof that the
property is missing**, and its presence in a README is not proof that it
is there.
