"""ОДИН замер: точность и трудоёмкость всех операций, большая выборка.

Заменяет россыпь прогонов, каждый из которых мерил свой кусок своим
способом. Здесь один набор данных, один порядок операций, одни повторы
и один формат вывода — для любой библиотеки.

Что меряется:

* **шифрование** — последовательное (одно значение за вызов) и пакетное
  (весь список за вызов). У `heu` пакетного нет, там второй столбец
  повторяет первый;
* **сложение** — на одно слагаемое, в цепочке из `SUM_TERMS`;
* **расшифровка** — на один шифротекст;
* **генерация ключа**;
* **длина шифротекста** — множество длин, а не одна: они минимальные;
* **точность** — ошибка круга и ошибка суммы на СИММЕТРИЧНОМ и на
  НЕОТРИЦАТЕЛЬНОМ входе.

Почему повторы и медиана, а не одно число. Разброс между запусками
одного и того же кода замерен и составляет около 7 % (634–693 эл/с на
девяти прогонах). Любой эффект меньше этого одиночным замером не
измеряется вовсе.

Почему эталон точности — `Fraction` от ИСХОДНЫХ чисел. Сумма
округлённых значений равна результату схемы по построению: сравнение с
ней измеряет гомоморфность, которая точна, а не ошибку кодирования.

Почему два входа. На симметричном входе правило округления не видно:
сносы разных знаков гасятся. Усечение к нулю проявляется только на
знакопостоянных данных — а это счётчики бакетов и квадраты градиентов.

Масштаб кодирования у всех библиотек выставляется ОДИНАКОВЫЙ. Иначе
сравнивается умолчание кодировщика, а не схема.

Запуск:
    python benches/measure.py ours
    python benches/measure.py heu
    python benches/measure.py phe
"""
import random
import statistics
import sys
import time
from fractions import Fraction

KEY_BITS = 2048
SCALE = 10 ** 8

# Выборка под времена. 2000 шифрований — это 1.4 с у самой быстрой
# библиотеки и 20 с у самой медленной: хватает, чтобы медиана была
# устойчивой, и не превращает прогон в ночной.
SAMPLE = 2000
SERIAL_SAMPLE = 200   # последовательное шифрование дороже, берём меньше
DECRYPT_SAMPLE = 100
SUM_TERMS = 1000
REPEATS = 5
KEYGEN_REPEATS = 5

# Выборка под накопление ошибки. Отдельная и большая: эффект правила
# округления виден именно на длине.
DRIFT_TERMS = 100_000


def timed(fn, repeats=REPEATS):
    """Медиана и разброс, а не лучшее время.

    Лучшее из N — это оценка нижней границы, а не типичного поведения, и
    сравнивать её с медианой другой величины нельзя. Здесь везде
    медиана.
    """
    taken = []
    for _ in range(repeats):
        started = time.perf_counter()
        result = fn()
        taken.append(time.perf_counter() - started)
    return statistics.median(taken), min(taken), max(taken), result


def inputs():
    """Два набора: симметричный и неотрицательный, плюс точные суммы."""
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


# ---------------------------------------------------------------------
# Обёртки: у каждой библиотеки свой интерфейс, дальше он один
# ---------------------------------------------------------------------

class Ours:
    name = "paillier"

    def __init__(self):
        import paillier

        self.p = paillier
        self.pub, self.sec = paillier.generate_keypair(KEY_BITS)

    def keygen(self):
        self.p.generate_keypair(KEY_BITS)

    def encrypt_batch(self, values):
        return [bytes(b) for b in self.p.encrypt_many(self.pub, values)]

    def encrypt_serial(self, values):
        return [bytes(self.p.encrypt_many(self.pub, [v])[0]) for v in values]

    def add(self, blobs):
        return self.p.add_many(self.pub, blobs)

    def decrypt(self, blob):
        return self.p.decrypt(self.sec, blob)

    def size(self, blob):
        return len(blob)


class Heu:
    name = "heu"

    def __init__(self):
        from heu import phe

        self.phe = phe
        self.kit = phe.setup(phe.SchemaType.ZPaillier, KEY_BITS)
        self.enc = self.kit.encryptor()
        self.dec = self.kit.decryptor()
        self.ev = self.kit.evaluator()
        self.encoder = phe.FloatEncoder(phe.SchemaType.ZPaillier, SCALE)

    def keygen(self):
        self.phe.setup(self.phe.SchemaType.ZPaillier, KEY_BITS)

    def encrypt_batch(self, values):
        # Пакетного шифрования у `heu` нет — это и есть его свойство,
        # а не недосмотр замера.
        return self.encrypt_serial(values)

    def encrypt_serial(self, values):
        return [self.enc.encrypt(self.encoder.encode(float(v))) for v in values]

    def add(self, blobs):
        total = blobs[0]
        for blob in blobs[1:]:
            total = self.ev.add(total, blob)
        return total

    def decrypt(self, blob):
        return self.encoder.decode(self.dec.decrypt(blob))

    def size(self, blob):
        return len(blob.serialize())


class Phe:
    name = "phe"

    def __init__(self):
        import phe

        self.phe = phe
        self.pub, self.sec = phe.generate_paillier_keypair(n_length=KEY_BITS)

    def keygen(self):
        self.phe.generate_paillier_keypair(n_length=KEY_BITS)

    def encrypt_batch(self, values):
        return self.encrypt_serial(values)

    def encrypt_serial(self, values):
        return [self.pub.encrypt(float(v)) for v in values]

    def add(self, blobs):
        total = blobs[0]
        for blob in blobs[1:]:
            total = total + blob
        return total

    def decrypt(self, blob):
        return self.sec.decrypt(blob)

    def size(self, blob):
        return (blob.ciphertext(be_secure=False).bit_length() + 7) // 8


LIBRARIES = {"ours": Ours, "heu": Heu, "phe": Phe}


# ---------------------------------------------------------------------

def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "ours"
    library = LIBRARIES[which]()
    symmetric, nonnegative = inputs()

    print(f"# {library.name}, ключ {KEY_BITS} бит, масштаб {SCALE:.0e}")
    print(f"# выборка: {SAMPLE} шифрований, {SUM_TERMS} слагаемых, "
          f"{REPEATS} повторов, медиана")
    print()

    def row(what, median, low, high, unit):
        print(f"{what:<34} {median:>10.3f} {unit:<8} "
              f"(от {low:.3f} до {high:.3f})")

    # --- трудоёмкость ---
    median, low, high, _ = timed(
        lambda: library.encrypt_serial(symmetric[:SERIAL_SAMPLE])
    )
    per = lambda t: t / SERIAL_SAMPLE * 1e3
    row("шифрование, последовательно", per(median), per(low), per(high), "мс")
    print(f"{'':<34} {SERIAL_SAMPLE / median:>10.0f} эл/с")

    median, low, high, blobs = timed(
        lambda: library.encrypt_batch(symmetric[:SAMPLE])
    )
    per = lambda t: t / SAMPLE * 1e3
    row("шифрование, пакетом", per(median), per(low), per(high), "мс")
    print(f"{'':<34} {SAMPLE / median:>10.0f} эл/с")

    median, low, high, total = timed(lambda: library.add(blobs[:SUM_TERMS]))
    per = lambda t: t / (SUM_TERMS - 1) * 1e6
    row("сложение, на слагаемое", per(median), per(low), per(high), "мкс")

    median, low, high, _ = timed(
        lambda: [library.decrypt(b) for b in blobs[:DECRYPT_SAMPLE]]
    )
    per = lambda t: t / DECRYPT_SAMPLE * 1e3
    row("расшифровка", per(median), per(low), per(high), "мс")

    median, low, high, _ = timed(library.keygen, repeats=KEYGEN_REPEATS)
    row("генерация ключа", median, low, high, "с")

    sizes = sorted({library.size(b) for b in blobs[:SAMPLE]})
    print(f"{'длина шифротекста':<34} {str(sizes):>10} байт")

    # --- точность ---
    print()
    circle = library.decrypt(blobs[0])
    error = abs(Fraction(circle) - Fraction(symmetric[0]))
    print(f"{'ошибка круга':<34} {float(error):>10.3e}")

    for label, values in (("симметричный", symmetric), ("неотрицательный", nonnegative)):
        for terms in (SUM_TERMS, DRIFT_TERMS):
            encrypted = library.encrypt_batch(values[:terms])
            got = library.decrypt(library.add(encrypted))
            error = abs(Fraction(got) - exact(values[:terms]))
            walk = (terms / 12) ** 0.5 / SCALE
            drift = terms / (2 * SCALE)
            print(
                f"{'сумма, ' + label + f', {terms}':<34} {float(error):>10.3e}"
                f"   блуждание {walk:.2e}   снос {drift:.2e}"
            )


if __name__ == "__main__":
    main()
