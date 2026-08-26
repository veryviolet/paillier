"""Check a built wheel: it installs, imports and computes correctly.

A separate file rather than a string inside a workflow. The reason is
not tidiness: a multi-line command inside YAML means a heredoc or
escaping, and both break on one stray space — and break ONLY in CI,
where debugging costs one push per attempt.

Here it is an ordinary script: it runs locally exactly as it runs in CI
and fails with an ordinary traceback.

It lives in `scripts/`, not in `tests/`: `pytest` collects everything
under `tests/`, and a module with top-level code would execute during
collection.

Run: `python scripts/smoke_wheel.py`
"""
import sys

import paillier


def main():
    print("version:", paillier.__version__)

    pub, sec = paillier.generate_keypair(2048)

    # Round trip, homomorphism, a sign change and a NON-default scale all
    # at once: a check at the default would also pass on a build where
    # the scale is never read back out of the blob.
    blobs = [
        bytes(b)
        for b in paillier.encrypt_many(pub, [1.5, -2.25], scale_pow10=12)
    ]
    total = paillier.decrypt(sec, paillier.add_many(pub, blobs))
    assert abs(total - (-0.75)) < 1e-9, f"sum {total}, expected -0.75"

    # A refusal is as much part of the contract as a result. A wheel that
    # computes correctly but silently swallows NaN is not fit to ship.
    try:
        paillier.encrypt_many(pub, [float("nan")])
    except ValueError:
        pass
    else:
        raise AssertionError("NaN was encrypted instead of being refused")

    print("wheel is sound")


if __name__ == "__main__":
    sys.exit(main())
