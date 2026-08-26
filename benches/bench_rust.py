"""Замер привязки на Rust: те же операции и те же данные."""

import json
import time

import numpy as np
import paillier as rp

N = 200
SUM_SIZE = 100
REPEATS = 3

values = np.random.default_rng(12345).normal(scale=100.0, size=N)
expected_sum = float(values[:SUM_SIZE].sum())


def timed(fn, repeats=REPEATS):
    best = None
    for _ in range(repeats):
        start = time.perf_counter()
        result = fn()
        elapsed = time.perf_counter() - start
        best = elapsed if best is None else min(best, elapsed)
    return best, result


pub, sec = rp.generate_keypair(2048)

# Параллельно (как задумано)
t_par, blobs = timed(lambda: rp.encrypt_many(pub, values.tolist()))
# По одному — чтобы отделить выигрыш от параллелизма
t_one, _ = timed(lambda: [rp.encrypt_many(pub, [float(v)])[0] for v in values[:40]])

blobs = list(blobs)
t_add, total = timed(lambda: rp.add_many(pub, blobs[:SUM_SIZE]))
t_dec, got = timed(lambda: rp.decrypt(sec, total), repeats=5)

print(json.dumps({
    "lib": "guardora/paillier",
    "encrypt_ms": round(t_par / N * 1e3, 4),
    "encrypt_ms_serial": round(t_one / 40 * 1e3, 4),
    "add_us": round(t_add / (SUM_SIZE - 1) * 1e6, 2),
    "decrypt_ms": round(t_dec * 1e3, 4),
    "cipher_bytes": len(blobs[0]),
    "abs_error": abs(got - expected_sum),
    "note": "сложение включает разбор из байтов; сериализация встроена",
}))
