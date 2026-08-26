# The scheme and what it assumes

## What is computed

```
c = (1 + m·n) · hs^r  mod n²
```

where `hs = h^n mod n²`, `h = −x² mod n`, and `r` is a random number of
`|n|/2` bits, fresh for every message.

Textbook Paillier computes `c = g^m · r^n mod n²` with a **random
base** `r`. Here the base is fixed — `hs` lives for the whole life of
the key — and the exponent is what varies. This is the Damgård–Jurik
variant.

Why: a fixed base means its powers can be precomputed once, turning the
exponentiation into 171 multiplications instead of roughly 1200. Nearly
all of the speed comes from there.

## Why decryption is unchanged

```
hs^r = (h^n)^r = (h^r)^n mod n²
```

The factor has the form `ρ^n` with `ρ = h^r` — that is, it remains a
legitimate randomiser of ordinary Paillier. Decryption works without a
single change, and the key holder **does not need to know** which `hs`
the encrypting side chose.

## What this adds to the assumptions

Textbook Paillier rests on DCRA alone (the Decisional Composite
Residuosity Assumption). A short exponent requires a **second one**:
that `hs^r` with `|r| = |n|/2` is indistinguishable from `hs^r` with a
full-length `r`.

The assumption is standard and published. But it exists, and "secure
under DCRA" is not a sentence you can say here.

The full treatment — including a counterexample where the plaintext
falls out in seven seconds, and an account of what that counterexample
does **not** prove — is in
[Short-exponent security](../short-exponent-security.md).

## What is required of the key

**`ord(hs)` must be NON-SMOOTH.** Not "large" — non-smooth. On a key
with smooth `λ`, Pohlig–Hellman recovers `r` outright, and every
magnitude check passes happily while it does.

Safe primes give this by construction. With `p = 2p′+1`, `q = 2q′+1`
the group is `Z*_n ≅ Z_{2p′} × Z_{2q′}`, and the set of reachable orders
of `hs` is `{2, 2p′, 2q′, 2p′q′}` — no smooth value above two exists
among them at all. That is a consequence, not an observation; the check
lives in `tests/order_of_hs.rs`.

The usual cheaper alternative is Blum primes, where the argument is
that smooth `λ` is vanishingly rare for a random 1024-bit prime. That
argument is probabilistic — and a probabilistic argument is not a check:
nothing refuses a key that happens to be bad.

## What is validated

| check | where |
|---|---|
| `(p−1)/2` and `(q−1)/2` are prime | `keys::validate_private` |
| `\|p − q\|` is not small (Fermat) | same |
| modulus length within bounds | same |
| `hs` is not degenerate (`ord ≤ 2`) | `keys::derive_hs` |
| foreign modulus: oddness and length | `keys::validate_public` |

Skipping private key validation is a **compile error**, not an
oversight: `SecretKey` carries a `keys::Validated` witness — a
zero-sized type with a private field that cannot be constructed outside
its module by any means.

Validation of a FOREIGN modulus is deliberately limited to length and
oddness — *partial public key validation* per NIST SP 800-56B, which is
what everyone does. A poisoned modulus is not caught by it, and it is
not caught by any other check derivable from `n` alone either; the
reasoning is in the docstring of `validate_public`.
