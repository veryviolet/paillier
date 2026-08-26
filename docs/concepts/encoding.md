# Encoding and scale

## Fixed point

A floating-point number is encoded as an integer: `round(v · 10^e)`, and
decoded by dividing back. The scale `10^e` is chosen at encryption time
and defaults to `10^8`.

```python
blobs = paillier.encrypt_many(pub, values, scale_pow10=12)
```

## Round to nearest, not truncate

The rule was not chosen by taste.

Truncation toward zero biases **every** term downward in magnitude, by
`1/(2·10^e)` on average. On symmetric input the biases of opposite signs
cancel and the error grows as `√k`. On **sign-constant** input they add
up, and the error grows LINEARLY.

Federated learning is full of sign-constant data: bucket counters,
squared gradients, sums of absolute values.

Measured at the same scale of `10^8`:

| terms | truncation | rounding (what we do) |
|---|---|---|
| 1 000 | 4.98e-06 | 1.95e-08 |
| 10 000 | 5.02e-05 | 1.42e-07 |
| 100 000 | 5.00e-04 | 1.17e-06 |

The first column lands exactly on the drift line `k/(2·10^e)`; the
second stays at random-walk level. Over a hundred thousand terms that is
a factor of four hundred.

Which rule an encoder actually applies is established by a
**discriminating observation**, not inferred from the error numbers:
take a value whose scaled magnitude has fractional part 0.7 and look at
what comes back. `benches/acc_rounding.py` does exactly that for ours.

## The scale travels in the ciphertext

The first byte of the blob holds the power-of-ten exponent. Therefore:

* `decrypt` reads the scale **from the blob itself**;
* `add_many` **refuses** a batch that mixes scales;
* the two sides never negotiate a scale at all.

!!! warning "Why not a call parameter"

    A scale mismatch produces **not a refusal but a plausible wrong
    number**: same codes, same length, just a result smaller by `10^Δ`.

    And separately: the passive side builds a peer key from `n` alone,
    and `n` carries no scale. Configured "on the side", it would take
    the default and silently disagree with the key holder.

The cost is one byte out of 513 — 0.2 % of the length.

Rescaling ciphertexts to a common scale is impossible: rescaling means
multiplying the plaintext, and the plaintext is encrypted. So the
choices are to refuse or to return nonsense.

## Choosing a scale

The encoding error is `1/(2·10^e)` and it is **absolute** — independent
of the magnitude — but only while `|v|·10^e` is exactly representable in
`f64`, roughly up to `|v| ≈ 2^53/10^e`. Above that the product itself
gets rounded and the error becomes relative.

| `e` | error | upper bound on `\|v\|` |
|---|---|---|
| 8 (default) | 5e-09 | ~9e7 |
| 12 | 5e-13 | ~9e3 |
| 15 | 5e-16 | ~9e0 |

From `e = 12` onward the scheme's error on long sums drops **below the
resolution of `f64` itself**: the spacing between adjacent floats near a
sum of order `5e8` is about `1.2e-07`, while the encoding error over a
million terms is about `3e-10`. The result lands on the same float as
the exact sum, and raising the scale further gains nothing — it only
narrows the range.

The default stays at `8`: the widest input range is a sensible default,
and narrowing it for accuracy is a decision for whoever knows the data.

## Two edges to keep in mind

**Below.** Anything smaller in magnitude than `1/(2·10^e)` encodes to
zero. That is a property of fixed point, not a loss: at the default,
`4e-9` encodes to zero and decrypts to zero.

**Above.** See the table. Past the boundary the error becomes relative
and the model "error does not depend on magnitude" stops holding.

`NaN` and infinities are **refused** rather than turned into a credible
zero that would then travel into the sum. A gap in a feature column is
ordinary input, not an exotic case.
