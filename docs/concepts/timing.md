# Timing side channels

**This library does NOT provide constant time and does not claim to.**
Two channels are closed, one is open, named and measured. All three are
below, because the difference between "named" and "closed" is decisive
here.

## What "constant time" even means

Not "the same number of microseconds" — timing wanders with machine
load regardless. The requirement is different: **changing the secret
must not change observable behaviour**.

The secret here is the exponent `r`, fresh for every message. An
observer who learns `r` recovers the plaintext outright: compute `hs^r`
(base and modulus are public), divide the ciphertext by it, get
`1 + m·n`, subtract one, divide by `n`.

The observer is not a person with a stopwatch on the network — it is a
**process on the same machine**, sharing the CPU cache with us.

## Exponent-weight channel — CLOSED

The first version of the table skipped zero digits: a zero window meant
no multiplication. Time was then directly proportional to the number of
non-zero digits of `r`. Measured: from 0.2 µs on an empty exponent to
1576 on a full one, linear, at 6.1 µs per digit.

Closed by multiplying **at every window**, with `n² + 1` sitting in the
zero entry.

!!! note "Why `n² + 1` and not `1`"

    One is a single-limb number: GMP computes `result · 1` in one pass,
    and the following `% n²` returns immediately. A zero window is then
    nearly free again.

    How this was caught: I substituted one and expected a slowdown of
    one sixteenth. The measurement showed 0.6 % instead of 6.7 %, and I
    read that as good news — though the missing six percent *were* the
    work that was not being done.

    **Cheaper than expected is not a gift. It is a signal.**

Guarded by `tests/timing_channel.rs`. The criterion is the **slope** of
time against weight, not absolute time: absolute time depends on the
machine, slope does not.

## Cache channel — CLOSED

A table entry used to be fetched by an index equal to the secret digit.
The operation itself does not branch, but the **memory address depends
on the secret**, and a neighbour sharing the cache sees which line we
pulled in.

Now the whole row is read and the wanted entry is selected with an
arithmetic mask, with no branch anywhere. The sequence of addresses is
identical for any exponent.

The cost of that was measured and turned out not to be what I had
assumed. The code said "closing it would mean paying sixteen times
over" — a figure inflated by more than an order of magnitude: measured
**1–5 %**, invisible in an end-to-end run.

!!! note "Laid out in words, not bytes"

    Byte-wise constant-time reading cost +26 %; word-wise, a few
    percent. The price is bounded by the number of iterations, not by
    the volume of data.

## Leading-zeros channel — OPEN

The loop starts from one, and while the low digits of `r` are zero the
accumulator stays single-limb, making those multiplications cheaper.
Measured: about **−6.3 µs per leading zero**.

The size of the leak is the entropy of the run of leading zeros. A digit
is zero with probability `q = 2^−w`, the run length is geometric, and

```
H = [−(1−q)·lg(1−q) − q·lg q] / (1−q)
```

At the current window width `w = 6` that is **0.118 bits** out of 1024.

!!! info "The number follows from the window width"

    At `w = 4` the same formula gives 0.36. Widening the window from
    four bits to six cut the leak threefold without touching a single
    line of the loop. This is the only quantity in the repository that
    describes an **open** channel, so it has to follow from the code
    rather than survive an edit to it.

Against a `2^512` margin this is nothing, and the remainder is accepted
knowingly.

The only known cure is a redundant representation in which one is not
single-limb — that is, **Montgomery form**. It was rejected on speed,
and the connection deserves to be stated plainly: the rejected technique
is the only known cure for the remaining channel.

Guarded by `tests/timing_channel.rs::позиционный_остаток_не_вырос` — not
for absence, but for the remainder not growing.

## Decryption

There the secret is different, and worse: the exponent derives from `λ`,
the long-lived secret of the key. A leak during encryption costs
fractions of a bit about a one-shot `r`; a leak during decryption
accumulates over every decryption for the whole life of the key.

That is why exponentiation goes through `mpz_powm_sec` rather than
`mpz_powm`: GMP's documentation requires exactly this for secret
exponents. It costs a factor of 1.55, and it is the only place where we
pay for security in a big way.

## Nothing is claimed about other implementations

Whether any other Paillier library is constant-time is not asserted here
either way. **Absence of a stated guarantee is not proof that the
property is missing**, and its presence in a README is not proof that it
is there.
