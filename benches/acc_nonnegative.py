"""Накопление ошибки на ЗНАКОПОСТОЯННЫХ данных: где правило округления
перестаёт быть мелочью.

Кодировщики двух библиотек различаются правилом (`acc_rounding.py`):
`heu` усекает к нулю, наш округляет к ближайшему. На симметричном входе
разница почти не видна — сносы разных знаков гасятся, и обе растут как
`√k`. Но входы федеративного обучения сплошь и рядом знакопостоянные:
счётчики бакетов, квадраты градиентов, суммы модулей. Там усечение
смещает КАЖДОЕ слагаемое в одну сторону, и ошибка растёт ЛИНЕЙНО.

Ожидание, против которого сверяемся:

* округление к ближайшему — снос нулевой, остаётся `√(k/12)/scale`;
* усечение к нулю — снос `1/(2·scale)` на слагаемое, итого `k/(2·scale)`.

Масштаб у обеих одинаковый (1e8), иначе сравнивалось бы умолчание
кодировщика, а не правило.

Эталон — точная сумма ИСХОДНЫХ чисел в `Fraction`.

Запуск: `python benches/acc_nonnegative.py ours` либо `... heu`.
"""
import random
import sys
from fractions import Fraction

SCALE = 10 ** 8
SIZES = [1_000, 10_000, 100_000]
SPREAD = 1000.0


def values_and_reference():
    """Неотрицательные числа и точные суммы на каждом размере."""
    random.seed(20260826)
    values = [random.uniform(0.0, SPREAD) for _ in range(max(SIZES))]
    exact = Fraction(0)
    reference = {}
    for index, value in enumerate(values, start=1):
        exact += Fraction(value)
        if index in SIZES:
            reference[index] = exact
    return values, reference


def report(size, got, exact):
    error = float(abs(Fraction(got) - exact))
    random_walk = (size / 12) ** 0.5 / SCALE
    drift = size / (2 * SCALE)
    print(
        f"{size:>9} {error:>12.3e} {random_walk:>14.3e} {drift:>13.3e} "
        f"{error / random_walk:>10.1f}"
    )


HEADER = (
    f"{'k':>9} {'ошибка':>12} {'√(k/12)/S':>14} {'k/(2·S)':>13} {'к блужданию':>10}"
)


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "ours"
    values, reference = values_and_reference()
    print(f"вход неотрицательный, масштаб {SCALE:.0e}, эталон точный\n")
    print(HEADER)

    if which == "heu":
        from heu import phe as hp

        kit = hp.setup(hp.SchemaType.ZPaillier, 2048)
        enc, dec, ev = kit.encryptor(), kit.decryptor(), kit.evaluator()
        encoder = hp.FloatEncoder(hp.SchemaType.ZPaillier, SCALE)
        for size in SIZES:
            blobs = [enc.encrypt(encoder.encode(float(v))) for v in values[:size]]
            total = blobs[0]
            for blob in blobs[1:]:
                total = ev.add(total, blob)
            report(size, encoder.decode(dec.decrypt(total)), reference[size])
    else:
        import paillier as p

        pub, sec = p.generate_keypair(2048)
        for size in SIZES:
            blobs = [bytes(b) for b in p.encrypt_many(pub, values[:size])]
            report(size, p.decrypt(sec, p.add_many(pub, blobs)), reference[size])


if __name__ == "__main__":
    main()
