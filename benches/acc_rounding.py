"""Does the encoder round or truncate — by discriminating observation.

The error numbers hint at it indirectly (truncation gives an error √3
larger), but indirect is not proof.

The probe: a value whose scaled magnitude has fractional part 0.7.
Truncation toward zero drops it, rounding to nearest adds one. The
answers differ, and the answer names the rule.

Fractional part 0.7, not 0.5. A tie looks like the most telling probe,
but `1.0000005` is not exactly representable in binary `f64`, so
`value·scale` lands slightly below or slightly above the half — which
turns a probe of the tie-breaking rule into a probe of which way the
representation error fell. At 0.7 there is no tie at all.

Sign matters as much as magnitude. Truncation toward zero biases
downward IN MAGNITUDE on both sides, i.e. the bias is opposite to the
sign of the value; on symmetric input the biases cancel and `√k` is left,
on sign-constant input they accumulate linearly.

Run: `python benches/acc_rounding.py`
"""
import math

import paillier

KEY_BITS = 2048
SCALE_POW10 = 8


def what_was_done(value, scale, decoded):
    """Which rule explains the answer: truncation or rounding."""
    scaled = value * scale
    toward_zero = math.trunc(scaled)
    to_nearest = math.floor(scaled + 0.5) if scaled > 0 else math.ceil(scaled - 0.5)
    got = round(decoded * scale)

    if toward_zero == to_nearest:
        return f"probe does not discriminate ({got})"
    if got == toward_zero:
        return "truncation toward zero"
    if got == to_nearest:
        return "round to nearest"
    return f"neither: {got}"


def probes_for(scale):
    """Values whose `value·scale` has fractional part 0.7."""
    step = 0.7 / scale
    return [1 + step, -(1 + step), 2 + step, -(2 + step)]


def main():
    scale = 10 ** SCALE_POW10
    pub, sec = paillier.generate_keypair(KEY_BITS)

    print(f"{'input':>18} {'back':>18} {'what happened':>26}")
    for value in probes_for(scale):
        blob = bytes(paillier.encrypt_many(pub, [value], SCALE_POW10)[0])
        back = paillier.decrypt(sec, blob)
        print(f"{value:>18.11f} {back:>18.11f} "
              f"{what_was_done(value, scale, back):>26}")


if __name__ == "__main__":
    main()
