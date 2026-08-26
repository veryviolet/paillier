"""ONE benchmark: accuracy and cost of every operation, large sample.

It replaces a scattering of benchmarks, each measuring its own piece its
own way. Here there is one dataset, one order of operations, one repeat
count and one output format.

What is measured:

* **encryption** — serial (one value per call) and batched (the whole
  list per call);
* **addition** — per term, in a chain of `SUM_TERMS`;
* **decryption** — per ciphertext;
* **key generation**;
* **ciphertext length** — the set of lengths, not one: they are minimal;
* **accuracy** — round-trip error and sum error on SYMMETRIC and on
  NON-NEGATIVE input.

Why repeats and medians rather than a single number. The spread between
runs of identical code was measured at about 7 % (634–693 ops/s over
nine runs). Any effect smaller than that is not measured by a single run
at all.

Why the accuracy reference is a `Fraction` of the ORIGINAL numbers. The
sum of rounded values equals the scheme's result by construction:
comparing against it measures homomorphism, which is exact, not the
encoding error.

Why two inputs. On symmetric input the rounding rule is invisible:
biases of opposite signs cancel. Truncation toward zero shows up only on
sign-constant data — and that is what bucket counters and squared
gradients are.

Run: `python benches/measure.py`
"""
import random
import statistics
import time
from fractions import Fraction

import paillier

KEY_BITS = 2048
SCALE_POW10 = 8

# Sample size for timings. 2000 encryptions is a couple of seconds:
# enough for a stable median without turning the run into an overnight
# job.
SAMPLE = 2000
SERIAL_SAMPLE = 200   # serial encryption is dearer, take fewer
DECRYPT_SAMPLE = 100
SUM_TERMS = 1000
REPEATS = 5
KEYGEN_REPEATS = 5

# Sample size for error accumulation. Separate and large: the effect of
# the rounding rule shows up precisely with length.
DRIFT_TERMS = 100_000


def timed(fn, repeats=REPEATS):
    """Median and spread, not the best time.

    Best-of-N estimates a lower bound, not typical behaviour, and
    comparing it against another quantity's median is invalid. Medians
    everywhere here.
    """
    taken = []
    for _ in range(repeats):
        started = time.perf_counter()
        result = fn()
        taken.append(time.perf_counter() - started)
    return statistics.median(taken), min(taken), max(taken), result


def inputs():
    """Two sets — symmetric and non-negative — plus exact sums."""
    random.seed(20260826)
    symmetric = [random.gauss(0.0, 1000.0) for _ in range(DRIFT_TERMS)]
    random.seed(20260827)
    nonnegative = [random.uniform(0.0, 1000.0) for _ in range(DRIFT_TERMS)]
    return symmetric, nonnegative


def exact(values):
    total = Fraction(0)
    for value in values:
        total += Fraction(value)
    return total


def encrypt_batch(pub, values):
    return [bytes(b) for b in paillier.encrypt_many(pub, values, SCALE_POW10)]


def encrypt_serial(pub, values):
    return [
        bytes(paillier.encrypt_many(pub, [v], SCALE_POW10)[0]) for v in values
    ]


def main():
    pub, sec = paillier.generate_keypair(KEY_BITS)
    symmetric, nonnegative = inputs()

    print(f"# paillier {paillier.__version__}, {KEY_BITS}-bit key, "
          f"scale 1e{SCALE_POW10}")
    print(f"# sample: {SAMPLE} encryptions, {SUM_TERMS} terms, "
          f"{REPEATS} repeats, median")
    print()

    def row(what, median, low, high, unit):
        print(f"{what:<30} {median:>10.3f} {unit:<6} "
              f"(from {low:.3f} to {high:.3f})")

    # --- cost ---
    median, low, high, _ = timed(
        lambda: encrypt_serial(pub, symmetric[:SERIAL_SAMPLE])
    )
    per = lambda t: t / SERIAL_SAMPLE * 1e3
    row("encryption, serial", per(median), per(low), per(high), "ms")
    print(f"{'':<30} {SERIAL_SAMPLE / median:>10.0f} ops/s")

    median, low, high, blobs = timed(
        lambda: encrypt_batch(pub, symmetric[:SAMPLE])
    )
    per = lambda t: t / SAMPLE * 1e3
    row("encryption, batched", per(median), per(low), per(high), "ms")
    print(f"{'':<30} {SAMPLE / median:>10.0f} ops/s")

    median, low, high, _ = timed(
        lambda: paillier.add_many(pub, blobs[:SUM_TERMS])
    )
    per = lambda t: t / (SUM_TERMS - 1) * 1e6
    row("addition, per term", per(median), per(low), per(high), "us")

    median, low, high, _ = timed(
        lambda: [paillier.decrypt(sec, b) for b in blobs[:DECRYPT_SAMPLE]]
    )
    per = lambda t: t / DECRYPT_SAMPLE * 1e3
    row("decryption", per(median), per(low), per(high), "ms")

    median, low, high, _ = timed(
        lambda: paillier.generate_keypair(KEY_BITS), repeats=KEYGEN_REPEATS
    )
    row("key generation", median, low, high, "s")

    sizes = sorted({len(b) for b in blobs[:SAMPLE]})
    print(f"{'ciphertext length':<30} {str(sizes):>10} bytes")

    # --- accuracy ---
    print()
    circle = paillier.decrypt(sec, blobs[0])
    error = abs(Fraction(circle) - Fraction(symmetric[0]))
    print(f"{'round-trip error':<30} {float(error):>10.3e}")

    scale = 10 ** SCALE_POW10
    for label, values in (("symmetric", symmetric),
                          ("non-negative", nonnegative)):
        for terms in (SUM_TERMS, DRIFT_TERMS):
            encrypted = encrypt_batch(pub, values[:terms])
            got = paillier.decrypt(sec, paillier.add_many(pub, encrypted))
            error = abs(Fraction(got) - exact(values[:terms]))
            walk = (terms / 12) ** 0.5 / scale
            drift = terms / (2 * scale)
            print(
                f"{'sum, ' + label + f', {terms}':<30} {float(error):>10.3e}"
                f"   walk {walk:.2e}   drift {drift:.2e}"
            )


if __name__ == "__main__":
    main()
