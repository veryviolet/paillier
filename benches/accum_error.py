"""Накопление ошибки неподвижной точки — теперь ПРАВИЛЬНЫМ эталоном.

Первая редакция мерила не то. Она сравнивала результат схемы с точной
суммой ОКРУГЛЁННЫХ значений, а это ровно то, что схема обязана дать по
построению: измерялась гомоморфность, которая точна, а не накопление
ошибки округления. Отсюда и взялось 1.0e-08 на миллионе — подпись
входов без ошибки округления, а не свойство схемы.

Эталон верный — сумма ИСХОДНЫХ чисел, точно, в `Fraction`. Разница с
ним и есть накопленная ошибка кодирования.

Дополнительно печатается предсказание `√(k/12)/SCALE`: при равномерном
округлении с шагом `1/SCALE` ошибки складываются как случайное
блуждание. Совпадение с ним означает, что систематического сноса нет.

Чего этот прогон НЕ проверяет и проверить не может:

* вход здесь `±1000`, а модель «ошибка абсолютна и равна `1/(2·SCALE)`»
  верна, только пока `|v| · SCALE` представимо в f64 точно, то есть до
  `|v| ≈ 2^53/SCALE ≈ 9e7`. Выше ошибка становится ОТНОСИТЕЛЬНОЙ;
* вход СИММЕТРИЧЕН, поэтому снос правила округления здесь виден быть не
  может — сносы разных знаков гасятся. Для знакопостоянных данных
  `acc_nonnegative.py`.
"""
import random
import time
from fractions import Fraction

import paillier as p

BITS = 2048
SCALE = 10 ** 8
SIZES = [1_000, 10_000, 100_000, 1_048_576]


def main():
    random.seed(20260826)
    pub, sec = p.generate_keypair(BITS)
    print(f"модуль {BITS} бит, планка {2 ** 20} слагаемых")
    print("эталон — сумма ИСХОДНЫХ чисел, точно\n")
    print(f"{'k':>9} {'ошибка':>12} {'предсказание':>13} {'отношение':>10} {'сек':>6}")

    biggest = max(SIZES)
    values = [random.uniform(-1000, 1000) for _ in range(biggest)]

    exact = Fraction(0)
    exact_at = {}
    for index, value in enumerate(values, start=1):
        exact += Fraction(value)  # ИСХОДНОЕ число, а не округлённое
        if index in SIZES:
            exact_at[index] = exact

    for size in SIZES:
        started = time.perf_counter()
        blobs = [bytes(b) for b in p.encrypt_many(pub, values[:size])]
        got = p.decrypt(sec, p.add_many(pub, blobs))
        spent = time.perf_counter() - started

        error = abs(Fraction(got) - exact_at[size])
        error = float(error)
        predicted = (size / 12) ** 0.5 / SCALE
        print(
            f"{size:>9} {error:12.3e} {predicted:13.3e} "
            f"{error / predicted:10.2f} {spent:6.0f}"
        )


if __name__ == "__main__":
    main()
