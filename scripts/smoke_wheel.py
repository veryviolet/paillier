"""Проверка собранного колеса: ставится, импортируется, считает верно.

Отдельным файлом, а не строкой внутри workflow. Причина не в красоте:
многострочная команда внутри YAML — это heredoc или экранирование, а и
то и другое ломается от одного лишнего пробела, причём ломается ТОЛЬКО
в CI, где отладка стоит по одному пушу за попытку.

Здесь же это обычный скрипт: запускается локально ровно так же, как в
CI, и падает с обычным traceback.

Лежит в `scripts/`, а не в `tests/`: `pytest` собирает всё из `tests/`,
и модуль с кодом на верхнем уровне исполнился бы при сборе тестов.

Запуск: `python scripts/smoke_wheel.py`
"""
import sys

import paillier


def main():
    print("версия:", paillier.__version__)

    pub, sec = paillier.generate_keypair(2048)

    # Круг, гомоморфность, смена знака и НЕумолчальный масштаб разом:
    # проверка на умолчании прошла бы и на сборке, где масштаб из блоба
    # не читается вовсе.
    blobs = [
        bytes(b)
        for b in paillier.encrypt_many(pub, [1.5, -2.25], scale_pow10=12)
    ]
    total = paillier.decrypt(sec, paillier.add_many(pub, blobs))
    assert abs(total - (-0.75)) < 1e-9, f"сумма {total}, ожидалось -0.75"

    # Отказ — такая же часть договора, как результат. Колесо, которое
    # считает верно, но молча съедает NaN, негодно.
    try:
        paillier.encrypt_many(pub, [float("nan")])
    except ValueError:
        pass
    else:
        raise AssertionError("NaN зашифровался вместо отказа")

    print("колесо годно")


if __name__ == "__main__":
    sys.exit(main())
