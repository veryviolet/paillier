"""Сравнение реализаций Paillier: скорость и точность.

Один набор данных, одни операции, каждая библиотека своим интерфейсом.
Операции те, что нужны крипто-раунду: шифрование, сложение шифротекстов,
расшифровка, сериализация в байты и обратно.

Точность проверяется по кругу: зашифровать → сложить → расшифровать →
сравнить с суммой открытых чисел.
"""

import json
import statistics
import sys
import time

import numpy as np

KEY_BITS = 2048
N = 200          # сколько значений шифруем
SUM_SIZE = 100   # сколько складываем в одну сумму
REPEATS = 3


def timed(fn, repeats=REPEATS):
    best = None
    for _ in range(repeats):
        start = time.perf_counter()
        result = fn()
        elapsed = time.perf_counter() - start
        best = elapsed if best is None else min(best, elapsed)
    return best, result


def report(name, *, enc, add, dec, ser, deser, cipher_bytes, error, extra=""):
    print(json.dumps({
        "lib": name,
        "encrypt_ms": round(enc * 1e3, 4),
        "add_us": round(add * 1e6, 2),
        "decrypt_ms": round(dec * 1e3, 4),
        "serialize_us": round(ser * 1e6, 2) if ser is not None else None,
        "deserialize_us": round(deser * 1e6, 2) if deser is not None else None,
        "cipher_bytes": cipher_bytes,
        "abs_error": error,
        "note": extra,
    }))


values = np.random.default_rng(12345).normal(scale=100.0, size=N)
expected_sum = float(values[:SUM_SIZE].sum())


# ---------------------------------------------------------------- phe
def bench_phe():
    import phe

    pub, priv = phe.generate_paillier_keypair(n_length=KEY_BITS)

    t_enc, encrypted = timed(lambda: [pub.encrypt(float(v)) for v in values])

    def do_add():
        total = encrypted[0]
        for item in encrypted[1:SUM_SIZE]:
            total = total + item
        return total

    t_add_all, total = timed(do_add)
    t_dec, got = timed(lambda: priv.decrypt(total), repeats=5)

    raw = str(encrypted[0].ciphertext(be_secure=True)).encode()
    t_ser, _ = timed(
        lambda: str(encrypted[0].ciphertext(be_secure=True)).encode(),
        repeats=20,
    )

    report(
        "phe",
        enc=t_enc / N, add=t_add_all / (SUM_SIZE - 1), dec=t_dec,
        ser=t_ser, deser=None, cipher_bytes=len(raw),
        error=abs(got - expected_sum),
    )


# ---------------------------------------------------------------- heu
def bench_heu():
    from heu import phe as heu_phe

    kit = heu_phe.setup(heu_phe.SchemaType.ZPaillier, KEY_BITS)
    encryptor = kit.encryptor()
    evaluator = kit.evaluator()
    decryptor = kit.decryptor()
    encoder = heu_phe.FloatEncoder(heu_phe.SchemaType.ZPaillier)

    plain = [encoder.encode(float(v)) for v in values]
    t_enc, encrypted = timed(lambda: [encryptor.encrypt(p) for p in plain])

    def do_add():
        total = encrypted[0]
        for item in encrypted[1:SUM_SIZE]:
            total = evaluator.add(total, item)
        return total

    t_add_all, total = timed(do_add)
    t_dec, got_plain = timed(lambda: decryptor.decrypt(total), repeats=5)
    got = encoder.decode(got_plain)

    raw = encrypted[0].serialize()
    t_ser, _ = timed(lambda: encrypted[0].serialize(), repeats=20)
    t_deser, _ = timed(
        lambda: heu_phe.Ciphertext.load_from(raw), repeats=20,
    )

    report(
        "heu",
        enc=t_enc / N, add=t_add_all / (SUM_SIZE - 1), dec=t_dec,
        ser=t_ser, deser=t_deser, cipher_bytes=len(raw),
        error=abs(got - expected_sum),
    )


# ------------------------------------------------------------ lightphe
def bench_lightphe():
    from lightphe.cryptosystems.Paillier import Paillier

    cs = Paillier(keys=None, key_size=KEY_BITS)
    # lightphe работает с целыми: масштабируем так же, как наш код.
    SCALE = 10 ** 8
    ints = [int(round(float(v) * SCALE)) for v in values]

    t_enc, encrypted = timed(
        lambda: [cs.encrypt(i % cs.plaintext_modulo) for i in ints],
        repeats=1,
    )

    def do_add():
        total = encrypted[0]
        for item in encrypted[1:SUM_SIZE]:
            total = cs.add(total, item)
        return total

    t_add_all, total = timed(do_add, repeats=1)
    t_dec, got_int = timed(lambda: cs.decrypt(total), repeats=3)

    modulo = cs.plaintext_modulo
    signed = got_int if got_int < modulo // 2 else got_int - modulo
    got = signed / SCALE

    raw = str(encrypted[0]).encode()
    report(
        "lightphe",
        enc=t_enc / N, add=t_add_all / (SUM_SIZE - 1), dec=t_dec,
        ser=None, deser=None, cipher_bytes=len(raw),
        error=abs(got - expected_sum),
        extra="целочисленная, масштаб 1e8, чистый python",
    )


BENCHES = {"phe": bench_phe, "heu": bench_heu, "lightphe": bench_lightphe}

for name in sys.argv[1:] or list(BENCHES):
    try:
        BENCHES[name]()
    except Exception as error:  # noqa: BLE001
        print(json.dumps({
            "lib": name, "failed": f"{type(error).__name__}: {error}"[:200],
        }))
