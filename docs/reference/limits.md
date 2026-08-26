# Limits and refusals

Everything the library **refuses**, and why a refusal was chosen over a
plausible number.

## The general rule

A silent zero is worse than an exception. A `NaN` turned into a credible
zero and carried into a sum is indistinguishable from a real zero — and
a gap in a feature column is ordinary input, not an exotic case.

## The key

| condition | what happens |
|---|---|
| modulus shorter than 2048 bits | refused: below NIST SP 800-57 for 112 bits |
| modulus longer than 8192 bits | refused: denial-of-service guard |
| `(p−1)/2` or `(q−1)/2` not prime | refused: safe primes are required |
| `\|p − q\|` small | refused: factors by Fermat's method |
| `p = q` | refused: no CRT split exists |

The upper bound is **not about security, it is about denial of
service**. Building a peer key runs with the GIL released, and until it
returns the interpreter executes nothing at all, signal handlers
included.

A foreign modulus is cut off **by raw byte count, before any
arithmetic**. Previously `n²` was computed before the check: 64
megabytes from a peer bought 4.07 seconds of complete deafness. Now the
refusal does not look at the content at all, and its cost does not
depend on the input length — which is asserted by a test rather than
promised.

## The plaintext

| condition | what happens |
|---|---|
| `NaN`, `±inf` | refused |
| overflow when scaled | refused |
| magnitude above the key bound | refused |

The bound on a value is `n/2` shrunk by `2^20` to reserve headroom for a
sum. With a key of 2048 bits or more that is `2^2026`, while the largest
encodable `f64` is about `2^1024` — so in practice this check cannot
fire. It stands anyway: key length and scale are configurable, and a
defence against one combination is not a defence against another.

## The sum

| condition | what happens |
|---|---|
| empty batch | refused |
| more than `2^20` terms per call | refused |
| ciphertext outside `[1, n²)` | refused, with the term's index |
| mixed scales in a batch | refused, naming both scales |

!!! warning "The cap on terms is not a guarantee"

    It is per call. The result of `add_many` can be fed into a second
    call and the counter starts over; two lawful calls give `2^40`
    terms, and no check will see it — the ciphertext of a sum is
    indistinguishable from the ciphertext of a term.

    What really keeps sums in the group is the thousand bits of headroom
    between the key bound and what is encodable from `f64`.

## What is NOT checked

**That a ciphertext was made under this key.** It does not follow from
`n` alone. A foreign ciphertext will usually lead to a refusal on
decryption, but not always.

**That a ciphertext is invertible.** `add_many` checks only the range:
the value `n` falls inside `[1, n²)`, yet `gcd(n, n²) ≠ 1`, and a sum
containing it is spoiled. The refusal then arrives later, at the key
holder, with no address on it. This is deliberate: a `gcd` per term
would cost more than the operation itself.

**That the modulus is not poisoned.** Length and oddness are checked —
*partial public key validation* per NIST SP 800-56B, which is what
everyone does. A smoothness probe gives no guarantee at any bound: at
`B = 2^20` it costs 25 minutes and certifies `2^10` of work.

**That the scale byte is authentic.** It is not authenticated, and
flipping one byte yields a plausible wrong number. This adds nothing for
an active attacker — Paillier is malleable anyway — but the scale
mechanism defends against **oversight**, not against edits on the wire.
