"""Сколько стоит ключ. Отдельно, потому что разброс тут огромный.

Порождение безопасного простого — это поиск: кандидаты отвергаются, пока
не найдётся `p′` и `2p′+1` разом простые. Плотность около `2/ln²N`, и
время одного запуска гуляет в разы. Медиана по нескольким ключам —
единственное осмысленное число; одиночный замер здесь не значит ничего.

У `heu` простые блюмовы, а не безопасные, то есть ищется одно условие
вместо двух. Разница в цене ключа — прямое следствие разницы в
требовании к ключу, а не в качестве реализации.

Запуск: `python benches/keygen_cost.py ours` либо `... heu`.
"""
import statistics
import sys
import time

ROUNDS = 5
SIZES = [2048, 3072]


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "ours"
    print(f"{'бит':>6} {'медиана, с':>12} {'мин':>8} {'макс':>8}")

    if which == "heu":
        from heu import phe as hp

        def make(bits):
            hp.setup(hp.SchemaType.ZPaillier, bits)
    else:
        import paillier as p

        def make(bits):
            p.generate_keypair(bits)

    for bits in SIZES:
        taken = []
        for _ in range(ROUNDS):
            started = time.perf_counter()
            make(bits)
            taken.append(time.perf_counter() - started)
        print(
            f"{bits:>6} {statistics.median(taken):>12.2f} "
            f"{min(taken):>8.2f} {max(taken):>8.2f}"
        )


if __name__ == "__main__":
    main()
