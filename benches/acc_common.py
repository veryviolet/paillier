"""Общие входы и общий эталон для сравнения точности.

Эталон — ТОЧНАЯ сумма ИСХОДНЫХ чисел в `Fraction`. Не сумма
округлённых: та равна результату схемы по построению, и сравнение с
ней измеряет гомоморфность, а не ошибку кодирования.

Числа одни и те же для обеих библиотек: лежат в файле как сырые float64.

Причина именно в этом, а не в воспроизводимости. Здесь `random.gauss`
из стандартной библиотеки, и он от версии Python к версии не менялся —
тот же seed даёт тот же набор. Файл нужен затем, чтобы два прогона в
двух РАЗНЫХ окружениях (у `heu` свой Python 3.10, у нас 3.13) считали
заведомо одно и то же, не полагаясь на совпадение реализаций.

В докстринге стояло «версии numpy в двух окружениях разные» — а numpy
здесь не используется вовсе.
"""
import array
import pathlib
import random
from fractions import Fraction

HERE = pathlib.Path(__file__).parent
VALUES_FILE = HERE / "acc_values.f64"
COUNT = 1000
SPREAD = 100.0


def make_values():
    random.seed(20260826)
    values = array.array("d", (random.gauss(0.0, SPREAD) for _ in range(COUNT)))
    VALUES_FILE.write_bytes(values.tobytes())
    return list(values)


def load_values():
    """Те же числа, что у соседнего прогона; порождает, если их ещё нет.

    Без этой оговорки прогон работал бы только вторым по счёту, а
    запущенный первым падал бы на отсутствующем файле — то есть запуск
    поодиночке, ради которого файл и заведён, был бы невозможен.
    """
    if not VALUES_FILE.exists():
        return make_values()
    values = array.array("d")
    values.frombytes(VALUES_FILE.read_bytes())
    return list(values)


def exact_sum(values):
    total = Fraction(0)
    for value in values:
        total += Fraction(value)
    return total


def report(name, scale, roundtrip_got, sum_got, values):
    circle = abs(Fraction(roundtrip_got) - Fraction(values[0]))
    total = abs(Fraction(sum_got) - exact_sum(values))
    print(
        f"{name:>12} {scale:>8.0e} {float(circle):>13.3e} {float(total):>13.3e}"
    )


HEADER = f"{'библиотека':>12} {'масштаб':>8} {'круг':>13} {'сумма 1000':>13}"
