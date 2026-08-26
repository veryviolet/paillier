# Moving to `h^r`: what changes in the security argument

Analysis written before the implementation. The scheme variant is
published in the academic literature; what follows works through what it
costs in assumptions and what it demands of the key.

**Third edition.** The first demanded magnitude of `ord(h)` instead of
non-smoothness — on a key where all of its checks were green, the
plaintext fell out in seven seconds. The second fixed that but
introduced a smoothness probe as a defence against a substituted `hs`;
the probe gives no guarantee at any bound and cost 149 seconds to import
our own key. Here it is replaced by an arrangement in which there is
nothing to substitute.

## What exactly changes

**Before** (`fast-paillier`, `encryption_key.rs:78`):

```
r ← uniform from Z*_n
c = (1 + m·n) · r^n mod n²
```

**After:**

```
encrypting side, once per modulus n:
    x  ← random, gcd(x, n) = 1
    h  = −x² mod n
    hs = h^n mod n²

on every encryption:
    r ← random, |n|/2 bits
    c = (1 + m·n) · hs^r mod n²
```

Crucially: **the encrypting side derives `hs` itself** from `n` alone.
It does not travel over the wire and is not taken from someone else's
key.

## Why decryption does not break

```
hs^r = (h^n)^r = (h^r)^n mod n²
```

The factor has the form `ρ^n` with `ρ = h^r`, i.e. it remains a
legitimate randomiser of ordinary Paillier, and decryption
`L(c^λ mod n²)·µ mod n` works without a single change.

`ρ` may be reduced modulo `n` or modulo `n²` indifferently: `a^n mod n²`
depends only on `a mod n`, because for `a = b + kn` the binomial
expansion leaves only multiples of `n²` from the extra terms.

The key holder, moreover, **does not need to know which `hs` the
encrypting side chose**. Verified: two encrypting parties with different
`hs` under one `n` produce ciphertexts that add and decrypt correctly.

## The key requirement: the order must be NON-SMOOTH

Not "large". The distinction is decisive.

Counterexample: `p = 2·M_p+1`, `q = 2·M_q+1` where `M_p`, `M_q` are
products of distinct small primes. Then `p ≡ q ≡ 3 (mod 4)`,
`gcd(p−1, q−1) = 2`, `|p − q|` is large, `ord(h)` is 597 bits —
everything "checks out". But `λ` is smooth, Pohlig–Hellman recovers `r`
outright, and the plaintext is restored in 7 seconds.

The correct requirement: **`ord(hs)` must have a large prime divisor.**
(`ord(h)` and `ord(hs)` coincide: raising to the `n`-th power is an
isomorphism onto the subgroup of `n`-th residues.)

**Safe primes give this by construction**: with `p = 2p′+1`, `q = 2q′+1`
you get `λ = 2p′q′`, and the largest prime divisor is of the order of
half the modulus length. Verified by `tests/order_of_hs.rs`: twelve keys
on 256-bit primes and one of production length, all with
`ord(hs) = λ`.

Blum primes do **not** give this. They give something else:
`(h|p) = (h|q) = −1` while `(h|n) = +1`, i.e. `⟨h⟩ ⊆ J_n` — a property
about location, not about magnitude.

So **the main key check is that the primes really are safe**: `(p−1)/2`
and `(q−1)/2` are prime. Blumness, the `gcd` and the gap are auxiliary.

This statement stands as an executable test rather than as reasoning:
`tests/smooth_order_attack.rs` builds exactly such a counterexample — a
modulus longer than the floor, Blum primes, `gcd(p−1, q−1) = 2`, primes
far apart — and lifts the plaintext off it given **only `n` and the
ciphertext**. The method is Pollard's `p−1`; it factors the modulus,
after which decryption proceeds as for the key holder.

### What this counterexample does NOT prove

The first version of the test recovered the exponent `r` by
Pohlig–Hellman and called that an attack on the short exponent. That was
wrong twice over.

First, two quantities the observer does not have were carried across the
line "from here on, only `n` and the ciphertext": `hs` itself — derived
by the encrypting side from a random `x` and never handed out
(`dir(PublicKey)` contains only `modulus_bytes`, `exponent_bits`,
`plaintext_bound_bits`, `from_n`) — and the order of `hs`, which was
computed from `λ`, i.e. from `p` and `q`.

Second, and more importantly: such a key breaks **with no connection to
the short exponent at all**. A smooth `p−1` opens Pollard's `p−1`, and
that is a method against the MODULUS, not against the randomiser.
Canonical Paillier with a full-length exponent falls on the same key in
exactly the same way.

So the counterexample proves "a smooth `p−1` ruins any Paillier" — a
true statement, and enough to demand safe primes, but not the one that
was written. The non-smoothness requirement specific to the short
exponent is guarded by `DegenerateHs` (`tests/degenerate_x.rs`), and
with safe primes it holds by construction: the set of reachable orders
of `hs` is `{2, 2p′, 2q′, 2p′q′}`, so no smooth value above two exists
among them.

This is a CONSEQUENCE, not an observation. `Z*_n ≅ Z_{2p′} × Z_{2q′}`,
and `hs = h^n`; in `Z*_{n²} ≅ Z*_{p²} × Z*_{q²}`, raising to the power
`n = pq` leaves component orders dividing `2p′` and `2q′`, so `ord(hs)`
divides `lcm(2p′, 2q′) = 2p′q′`. Odd divisors are excluded (`h = −x²`
has even order), and `1` and `2` are cut off by `DegenerateHs`.

This used to say: "an exhaustive sweep of all `x` on five REAL keys".
Such a sweep is impossible on any machine — `Z*_n` at `|n| ≥ 2048` has
`2^2047` elements — and there was no artefact behind the phrase. The
statement was true; the evidence was invented.

What exists now (`tests/order_of_hs.rs`): a sweep that is HONESTLY
exhaustive, but on a toy key `p = 23`, `q = 59`, where the search runs
over 1354 values and covers all of them; a sample of twelve keys on
256-bit primes; and one key of production length, so that "the argument
does not depend on length" is not left as words.

### Blum primes rest on statistics, not on construction

The usual alternative is Blum primes — cheaper to find, and the security
argument then rests on smooth `λ` being practically nonexistent for a
random 1024-bit prime. That argument is probabilistic, and a
probabilistic argument is not a check: nothing in such an
implementation refuses a key that happens to be bad.

We take the strict side deliberately, and pay for it in key generation
time.

## Why `hs` is not imported

An implementation could put `hs` into the public key and accept it off
the wire. Then `h` is not published either, so nobody can verify
`hs = (−x²)^n` even in principle.

Verifying an imported `hs` by computation is **impossible**, and that is
not a question of diligence. The probe "`hs^E ≠ 1` for `E` the product
of primes up to `B`" certifies only `√B` of work at bound `B`, while
costing `π(B)·|n|` squarings:

| `B` | `π(B)` | cost at `\|n\| = 3072` | certifies |
|---|---|---|---|
| `2^16` | 6 542 | 2 min | `2^8` |
| `2^20` | 82 025 | 25 min | `2^10` |
| `2^24` | 1 077 871 | 5.5 h | `2^12` |

To certify 128 bits you would need `B = 2^256`. On top of that the probe
is blind to exponents: Pohlig–Hellman costs `Σ eᵢ·√pᵢ`, and a key whose
prime factors are all below 500 passes the probe at `2^20` while giving
up the plaintext in 0.1 seconds.

**Hence `hs` is not imported but derived.** The encrypting side takes
its own `x` and computes `hs` from `n` alone — 0.30 s for a peer key,
computed once and cached. There is nothing to substitute.

The residual risk is a malicious **`n`** with smooth `λ`. No computation
over `(n, hs)` catches it, and it applies to any variant of the scheme,
the original included. In our protocol `n` comes from the key holder,
who decrypts everything we send them anyway — so such a substitution
buys nothing.

## The threat model in our protocol

The key is generated by the active side, which **also encrypts with
it**: key holder and encrypting party are the same.

We encrypt under a foreign key in exactly one place — the zeros of empty
buckets on the passive side. Whatever could be learned there by
substitution, the active side already gets by the protocol's design.
The wire is under mTLS.

So there is no acute threat here. Deriving `hs` in place instead of
importing it is done not for that reason but because it is **simpler**
than importing with validation, and removes a whole class of
possibilities without requiring a single check.

## The security margin of a short exponent

Let `ord(hs) = S · L`, where `S` is the smooth part — a product of small
primes `pᵢ` with exponents `eᵢ`.

```
max( Σ eᵢ·√pᵢ ,  2^(|r|/2) / √S )
```

The first term is Pohlig–Hellman over the smooth part. The second is
Pollard's kangaroo over an interval **shortened by that same smooth
part**: the logarithm modulo `S` comes cheap, leaving the kangaroo an
interval of length `2^|r|/S`, i.e. `2^(|r|/2)/√S` steps.

This used to say

```
min( 2^(|r|/2),  √(largest prime divisor of ord(hs)) )
```

which is wrong twice over. First, the kangaroo term there does not know
about `S`: the formula judges by the LARGEST prime divisor, whereas what
shortens the attacker's work is the smooth part. Second, `min` picks the
cheaper of two attacks, but the real attack is one and combines both
parts.

The difference is not academic: a key with `ord(hs) = 2^100 · L` is
rated `2^512` by the old formula where the real cost is `2^462`.

On our keys there is no difference — `ord(hs) = 2p′q′`, so `S = 2`, and
both formulas agree. But this is the CRITERION a key is judged by, and
agreeing with the correct one in a single special case is not enough for
a criterion.

The estimate `2^(|r|/2)` on its own is wrong too: on a smooth key it
gives `2^152` where the real cost is seven seconds.

### The `|n|/2` exponent is four times longer than needed, and that is a decision

Compute by the formula above. At `|n| = 2048` the exponent gives
`2^512`, at 3072 it gives `2^768`. The modulus itself is worth 112–128
bits (NIST SP 800-57). So the exponent is protected four times better
than the key it guards: `|r| = 256` would give `2^128` — level.

What this costs in speed. Measured (`benches/exponent_length.rs`,
`|n| = 2048`, median of five series):

| exponent | windows | `pow_by_table` |
|---|---|---|
| 1024 bits (current) | 171 | 1048 µs |
| 512 | 86 | 502 µs |
| 256 | 43 | 262 µs |

Full sequential encryption on the same machine is 1006–1050 µs per
element (`benches/measure.py`), median 1020. So the constant part,
independent of exponent length, is **under twenty µs**, about two
percent. Hence:

| exponent | total time | ops/s per thread |
|---|---|---|
| 1024 bits | 1020 µs | 980 |
| 512 | ~520 µs | ~1900 |
| 256 | ~280 µs | **~3500** |

Shortening to 256 bits would therefore buy roughly a factor of three and
a half in single-threaded throughput.

Two caveats, both substantial.

First, the numbers are DERIVED by subtraction, not measured end to end:
the exponent length is not configurable from outside, it follows rigidly
from `|n|`.

Second, the constant part is the difference of two independently
measured quantities of about 1030 µs each, so its own uncertainty is
comparable to itself. The right-hand column is rounded to the nearest
hundred for exactly that reason: these measurements do not support more
precision.

The numbers in this section have changed three times, and only once
because of a refinement. First it said "about 2600 ops/s", which
followed from no measurement at all; then `2360–2630`, derived honestly
but at `WINDOW_BITS = 4`. The current ones are at six bits and have
nothing to do with the earlier code.

I had an argument here, and it turned out to be **wrong**. I wrote that
at `|r| = |n|/2` the value `hs^r` is statistically close to uniform on
`⟨hs⟩`, and that at 256 bits there is no such closeness — i.e. that
shortening changes the basis of indistinguishability.

The premise is false. `hs = h^n`, and in `Z*_{n²} ≅ Z*_{p²} × Z*_{q²}`
raising to the power `n = pq` leaves component orders `2p′` and `2q′`,
so `ord(hs) = lcm(2p′, 2q′) = 2p′q′ = λ`. A drop to `2p′` or `2q′`
happens with probability `1/q′`, `1/p′` — vanishingly rare.

This used to say "**400 out of 400** gave the full `λ`" — numbers with
no artefact behind them, like "five real keys" above. The check exists
now and says exactly what it does: `tests/order_of_hs.rs` — twelve keys
on 256-bit primes and one of production length, all with `ord(hs) = λ`.

So the order is not `2^(|n|/2)` but `≈ 2^(|n|−1)`. At `|n| = 2048` a
1024-bit exponent covers `2^1024` out of `2^2047` — a fraction of
`2^−1023`, and the statistical distance to uniform is `1 − 2^−1023`.
**There is no statistical closeness even at `|n|/2`.**

Hence the correct framing of the choice: both options rest on the SAME
assumption — the short-exponent one, item 1 below — and differ only in
the size of the margin, `2^512` against `2^128`. That does not make the
shortening free: narrowing the margin fourfold in bits is real. But the
decision must be made on the margin, not on "a narrower foundation": the
foundation is the same.

## Requirements on our key generation

What the crate provides: `decryption_key.rs:31-32` calls
`generate_safe_prime(rng, 1536)` twice, and `backend.rs:115-148` builds
`p′`, tests it for primality, takes `p = 2p′+1` and tests again. Genuine
safe primes.

What the crate does **not** do:

* **there is no `|p − q|` check in it at all.** The property holds
  probabilistically, and a probabilistic property is not a check — so an
  explicit one has to be added on our side.
* **`from_primes` and deserialisation bypass everything.** Only `p ≠ q`,
  `λ ≠ 0` and invertibility of `λ` are checked. And the crate's own
  docstring on `from_primes` states that the primes **must** be safe —
  without checking it.

So "our keys satisfy the requirements automatically" is true only for
the `generate_keypair` path; everything else has to be validated.

Plus, when deriving `h` we check the sign:
`jacobi(h, p) = jacobi(h, q) = −1`. If the sign is lost and `h = x²`
results, the order drops while every correctness check stays green. The
check is only possible where `p` and `q` are available, i.e. at the key
holder.

## The assumptions that get added

1. **Short exponent.** `h^r` with short `r` is indistinguishable from
   `h^R` with a full-length one. Standard, published, but new relative
   to the original scheme.
2. **DCR restricted to `J_n`.** The randomiser ranges over an
   index-two subgroup. This does not give away the plaintext, but our
   ciphertexts are publicly distinguishable from stock ones: all of them
   have Jacobi symbol `+1`, whereas stock ones split roughly evenly. The
   scheme's fingerprint is visible on the wire.
3. **Constant time in `r`.** The secret has moved from the base to the
   exponent: it used to be a secret base and a public exponent `n`, now
   it is a public base and a secret exponent. The window table is
   indexed by its bits — a target for cache measurement, and recovering
   `r` yields `m`.

A fourth assumption — about a second field in the public key — is gone:
`hs` does not travel over the wire, the key stays a single `n`, there is
nothing to lose.

## How the implementation is checked

1. Round trip against the crate's unmodified decryption: positive,
   negative, zero, range boundaries.
2. Homomorphism, including a sum crossing zero.
3. Compatibility: a ciphertext of the new form decrypts with the stock
   function — a check of the claim `hs^r = (h^r)^n`.
4. **Different `hs` under one `n` add up.** Two encrypting parties
   derive their own `hs`; the sum of their ciphertexts decrypts
   correctly. Without this, deriving in place has no right to exist.
5. A thousand encryptions of one value — all distinct.
6. **Randomiser collision across DIFFERENT plaintexts.** Check 5 is
   blind to that, and it is exactly what reusing `r` after a process
   fork with a shared seed looks like. The criterion is computed from
   the public key alone: `(c₁·c₂⁻¹ mod n²) mod n ≠ 1`.
7. **The primes really are safe**: `(p−1)/2` and `(q−1)/2` are prime.
   The main key check.
8. Blumness, `gcd(p−1, q−1) = 2`, `|p − q|` — auxiliary, each with its
   own refusal.
9. The sign of `h`: `jacobi(h, p) = jacobi(h, q) = −1`.
10. The exponent length is pinned BY NUMBER and computed from the ACTUAL
    length of `n`. It must be checked at a size where the requested and
    actual values diverge — otherwise the test is green by coincidence.
11. The key's end-to-end path: serialise → transmit → encrypt → decrypt.
12. **Randomisation on the `from_n` path, not only at the key holder.**
    All randomisation checks used to stand on the owner's key, and the
    mutation "`hs = 1` only in `from_n`" passed the whole suite — that
    is, there was no privacy for exactly the party the technique exists
    for.
13. **A floor on key length.** There was none at all, and
    `generate_keypair(32)` returned a 32-bit modulus with a green suite.
    A refusal is asserted, because everything else on such a key is
    fine.
14. **The foreign modulus.** A poisoned `n` yields a poisoned `hs`
    however diligently it is derived in place. Two things are checked:

    - oddness;
    - length, floor and ceiling.

    And that is **all** — precisely *partial public key validation* from
    NIST SP 800-56B, i.e. what everyone does. Neither closes the case
    "no privacy but a correct round trip": a short modulus weakens
    privacy rather than removing it. The checks that did close such
    cases have been removed; what that costs is below.

### Why the foreign-modulus probes are gone

There used to be three more probes here — trial division by small
primes, Brent's rho and Pollard's `p−1` — plus a compositeness check.
All removed, and the analysis is worth recording, because the path to
them was an error of reasoning rather than an oversight.

The argument was: a poisoned modulus opens the passive side's
ciphertexts to any eavesdropper, while the key holder loses nothing, so
they might well do it. The argument is correct. What is incorrect is the
conclusion that the modulus should therefore be checked by computation.

**It does not work.** From `n` alone you cannot establish that it is a
product of two large distinct primes: that is factorisation. Any probe
gives a bound and costs exactly as much as stepping over it costs the
attacker, who reads the sources and picks a factor beyond the bound.
Measured: rho with a `2^16` budget reaches about 32 bits, and a 40-bit
safe factor — the very example the probe was written for — passed
straight through it.

**It is expensive.** The probes cost two thirds of parsing a foreign key
(0.46 s out of 0.69 s at `|n| = 2048`) and tripled the window during
which the node does not answer signals: from 2.4 to 6.8 s on a maximal
modulus, with the GIL released. That is, the denial-of-service defence
itself became a denial of service.

**It is the wrong place.** The problem is solved not by a passive check
but by a proof of the modulus's form from its owner:
Gennaro–Micciancio–Rabin for square-freeness, van de Graaf–Peralta for
"exactly two primes". That is finite work with a clear end, but its
place is a challenge-response in the node handshake, not a function in a
library.

So the correct framing is: **`validate_public` cannot be finished, but
the problem can.** Until such a proof exists, trust in `n` comes from
mTLS and the invitation, and that is a CHOICE, not an impossibility.

### Compositeness was removed by a separate decision, and the three arguments above do not apply to it

This has to be separated honestly. The check that `n` is not prime and
not an exact prime power was removed together with the probes, but it is
**not a probe**:

- `is_probably_prime` is a decision procedure, not a bounded search. It
  has no threshold for an attacker to step over: a prime modulus is
  caught reliably;
- it costs 2.3 ms at `|n| = 2048` — half a percent of the 0.46 s the
  probes were removed for;
- and it catches more than malice: a peer with a broken generator that
  sends a prime is accepted silently.

So "it does not work" is false for it, "it is expensive" is false, and
"wrong place" speaks about the ideal cure rather than about why a
reliable check should be dropped today.

It was removed on a different ground: **we do exactly what the standard
prescribes and no more.** NIST SP 800-56B does not include compositeness
in partial public key validation. That is a decision about the library's
boundaries, not a conclusion from the reasoning above.

The price of that decision, measured and written down so it cannot be
missed: a 2048-bit prime `n` is accepted by `from_n` in 0.010 s, the
ciphertexts are distinct — randomisation intact, round trip intact — and
an observer holding only `n` reads every plaintext, because `λ = n−1`. A
prime power passes the same way. Reverting costs two lines.

15. **Headroom for the sum.** Per-value range checking is not enough: on
    a 1024-bit key three lawful values added up to a finite, plausible
    number of the wrong sign. Headroom is reserved at encryption time,
    and `add_many` holds a cap per call.

    That pair is NOT a guarantee, and the code says so: the counter is
    per call, the result of `add_many` can be fed into a second call,
    and two lawful calls give `2^40` terms. What holds the invariant is
    the relation between the key floor and what is encodable from `f64`
    at all: `2^2026`–`2^2027` against `2^1024`. Two values because the
    product of two 1024-bit primes lands on both 2048 and 2047 bits;
    a single `2^2027` used to stand here and was refuted by every other
    key. It is asserted by a number — but a number derived from the
    ACTUAL modulus length (`modulus_bits − 21`), not a literal, which is
    why the test never knew about the discrepancy.

    The bound is computed by ONE function for both the encryption
    predicate and the getter. Separately, a mutation of the multiplier
    in the predicate passed the whole suite — the getter kept returning
    the right number. That is the same defect as with the exponent
    length, repeated one line over.

16. **Refusal, not panic.** `PanicException` inherits `BaseException`
    and passes straight through a caller's `except Exception`.

## What this transition does not give

A precomputed pool of ready `hs^r` values. It would speed things up
further, but reusing `r` breaks semantic security. Only with a
guarantee that every value is spent exactly once — and that is separate
work.
