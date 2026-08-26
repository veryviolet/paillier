"""Шифрование коротким показателем.

Прежде проверок на него не было ни одной, и сьют оставался зелёным на
коде, у которого приватности нет: мутация «показатель 8 бит» проходила,
и «`hs = 1`» тоже.

Запускается собранным модулем:
    PYTHONPATH=<где лежит paillier.so> python -m pytest tests/encryption.py
"""

import math
import time

import pytest

import paillier as p

# Нижняя граница длины модуля. Меньше нельзя — `generate_keypair`
# откажет, и правильно сделает.
BITS = 2048

# 2050 просится отдельно: произведение двух простых по 1025 бит выходит
# на 2049 бит, и всё, что считает длину показателя от ЗАПРОШЕННОЙ
# величины, здесь расходится с тем, что считает от фактической.
ODD_BITS = 2050


@pytest.fixture(scope="module")
def key():
    return p.generate_keypair(BITS)


def exponent_bits_of(pub):
    """Ожидаемая длина показателя — половина ФАКТИЧЕСКОГО модуля."""
    modulus_bits = int.from_bytes(pub.modulus_bytes(), "big").bit_length()
    return ((modulus_bits // 2 + 7) // 8) * 8


def one(pub, value):
    return list(p.encrypt_many(pub, [value]))[0]


# ---------------------------------------------------------------------
# Круг и гомоморфность
# ---------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    0.0, 1.0, -1.0, 0.5, -0.5, 1e-8, -1e-8, 12345.678, -98765.4321,
])
def test_круг(key, value):
    pub, sec = key

    assert p.decrypt(sec, one(pub, value)) == pytest.approx(value, abs=1e-7)


def test_гомоморфность_включая_переход_через_ноль(key):
    pub, sec = key
    blobs = list(p.encrypt_many(pub, [10.0, -3.5, -20.0, 1.25]))

    total = p.decrypt(sec, p.add_many(pub, blobs))

    assert total == pytest.approx(10.0 - 3.5 - 20.0 + 1.25, abs=1e-6)


# ---------------------------------------------------------------------
# Рандомизация — то, что теряется молча
# ---------------------------------------------------------------------

def test_одно_значение_даёт_разные_шифротексты(key):
    """Ловит `hs` вырожденного порядка и потерянный вызов ГСЧ."""
    pub, _ = key

    blobs = p.encrypt_many(pub, [7.0] * 200)

    assert len({bytes(b) for b in blobs}) == 200


def test_длина_показателя_закреплена_ЧИСЛОМ(key):
    """Половина длины модуля, и это проверяется прямо.

    Судить по столкновениям среди шифрований нельзя: замерено, что при
    показателе в 64, 128 и 192 бита совпадений среди шестисот шифрований
    не бывает вовсе, а стойкость при 64 битах уже `2^32` — минуты
    работы. Такая проверка ловит только обвал до границы дней рождения,
    то есть примерно до восьми бит.

    Так выглядит опечатка в единицах — `bits/2` байт вместо бит — или
    правка `/2` на `/4`.
    """
    pub, _ = key

    assert pub.exponent_bits == exponent_bits_of(pub)


def test_ключ_пира_берёт_ту_же_длину_показателя(key):
    """Две формулы в двух местах разъезжаются молча: `generate_keypair`
    считала от запрошенных бит, `from_n` — от фактических."""
    pub, _ = key

    peer = p.PublicKey.from_n(pub.modulus_bytes())

    assert peer.exponent_bits == pub.exponent_bits


def test_длина_показателя_совпадает_когда_модуль_короче_запроса():
    """Тест выше был зелен на 1024 битах по совпадению.

    При запросе 1026 модуль выходил на 1025 бит: владелец брал 520 байт
    от ЗАПРОШЕННОЙ величины, пир — 512 от фактической, и шифротексты
    двух сторон под одним ключом получали показатели разной длины.

    Расхождение возникает не всегда: произведение двух простых по
    `bits/2` бит выходит и на `bits`, и на `bits−1` — как лягут старшие
    биты. Поэтому ключ ИЩЕТСЯ, а не берётся первый попавшийся: тест,
    полагающийся здесь на удачу, краснеет через раз, и я это уже
    получил.
    """
    attempts = 0
    while True:
        attempts += 1
        assert attempts <= 20, "за 20 попыток не нашёлся модуль короче запроса"
        pub, _ = p.generate_keypair(ODD_BITS)
        modulus_bits = int.from_bytes(pub.modulus_bytes(), "big").bit_length()
        if modulus_bits < ODD_BITS:
            break

    peer = p.PublicKey.from_n(pub.modulus_bytes())

    assert exponent_bits_of(pub) != ((ODD_BITS // 2 + 7) // 8) * 8, (
        "размер выбран так, чтобы формулы от фактической и от запрошенной "
        "величины давали РАЗНОЕ — иначе мутация не поймается"
    )
    assert pub.exponent_bits == exponent_bits_of(pub)
    assert peer.exponent_bits == pub.exponent_bits


def test_шифрования_одного_значения_не_повторяются(key):
    """Отдельно от длины: ловит обвал рандомизатора до горстки
    значений."""
    pub, _ = key

    blobs = p.encrypt_many(pub, [1.0] * 600)

    assert len({bytes(b) for b in blobs}) == 600


def test_рандомизатор_не_повторяется_между_вызовами(key):
    """Проверка выше слепа к повторному использованию `r` при РАЗНЫХ
    открытых текстах — а именно так выглядит ветвление процесса с общим
    зерном.

    Признак считается только по публичному ключу: если `r` совпал, то
    `c₁·c₂⁻¹ ≡ 1 + (m₁−m₂)·n`, то есть по модулю `n` даёт единицу.
    """
    pub, _ = key
    n = int.from_bytes(pub.modulus_bytes(), "big")
    nn = n * n

    left = int.from_bytes(bytes(one(pub, 11.0)), "big")
    right = int.from_bytes(bytes(one(pub, 22.0)), "big")

    ratio = left * pow(right, -1, nn) % nn
    assert ratio % n != 1, "рандомизатор совпал у двух шифрований"


@pytest.fixture(scope="module")
def peer(key):
    """Ключ пира: собран из ОДНОГО модуля, `hs` выведен на месте."""
    pub, _ = key
    return p.PublicKey.from_n(pub.modulus_bytes())


def test_ключ_пира_рандомизирует_шифрование(peer):
    """Все проверки рандомизации стояли на ключе владельца, а путь пира
    проверялся только на круг и сложение.

    Мутация «`hs = 1` в `from_n`» проходила сьют целиком: `c = 1 + m·n`
    ровно, то есть приватности нет у той самой стороны, ради которой
    вывод `hs` на месте и существует.
    """
    blobs = p.encrypt_many(peer, [7.0] * 200)

    assert len({bytes(b) for b in blobs}) == 200


def test_рандомизатор_пира_не_повторяется_между_вызовами(peer):
    """То же, что и для владельца: признак считается по одному
    публичному ключу, без знания `r`."""
    n = int.from_bytes(peer.modulus_bytes(), "big")
    nn = n * n

    left = int.from_bytes(bytes(one(peer, 11.0)), "big")
    right = int.from_bytes(bytes(one(peer, 22.0)), "big")

    ratio = left * pow(right, -1, nn) % nn
    assert ratio % n != 1, "рандомизатор совпал у двух шифрований"


def test_шифротекст_пира_не_равен_кодированию_открытого_текста(peer):
    """Прямой признак `hs = 1`: тогда `c` в точности `1 + m·n`.

    Проверка выше ловит это через различие шифротекстов, но ловит
    косвенно; здесь предъявляется само значение.
    """
    n = int.from_bytes(peer.modulus_bytes(), "big")

    blob = int.from_bytes(bytes(one(peer, 3.5)), "big")

    assert blob != 1 + round(3.5 * 10**8) * n


# ---------------------------------------------------------------------
# Отказы вместо правдоподобного числа
# ---------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    float("nan"), float("inf"), float("-inf"),
])
def test_нефинитные_отвергаются(key, value):
    """Прежде превращались в достоверный ноль и уезжали в сумму."""
    pub, _ = key

    with pytest.raises(ValueError):
        p.encrypt_many(pub, [value])


@pytest.mark.parametrize("value", [1.7976931348623157e308, -1.7976931348623157e308])
def test_переполнение_при_масштабировании_отвергается(key, value):
    """`v · SCALE` уходит в бесконечность, и кодирования не существует.

    Прежде такое значение возвращалось как `−4.8e299` — конечное число
    не того знака.
    """
    pub, _ = key

    with pytest.raises(ValueError):
        p.encrypt_many(pub, [value])


def test_запас_под_сумму_перекрывает_весь_диапазон_f64(key):
    """Проверка диапазона на 2048-битном ключе сработать НЕ МОЖЕТ, и это
    надо утверждать числом, а не подбирать значение, которое она
    отвергнет.

    Прежний тест подавал `1e300` и требовал отказа. Он был зелен только
    потому, что стоял на 1024-битном ключе, где `n/2 ≈ 1e308`. С нижней
    границей в 2048 бит `1e300` — совершенно законное значение, и отказа
    на нём быть не должно.

    Утверждается то, что действительно держит приватность от
    беззвучного переполнения: запас под сумму с большим отрывом
    перекрывает всё, что вообще кодируется из `f64`.
    """
    pub, sec = key
    modulus_bits = int.from_bytes(pub.modulus_bytes(), "big").bit_length()
    largest_encodable = 1.79e300

    # РАВЕНСТВО, а не «больше чем». Прежде стояло
    # `1024 < plaintext_bound_bits` при зазоре в тысячу бит — такому
    # неравенству удовлетворяет и совершенно неверное значение, и
    # мутация геттера на `n.significant_bits()` (ошибка в 21 бит)
    # проходила сьют целиком.
    assert pub.plaintext_bound_bits == modulus_bits - 21

    assert int(largest_encodable * 10**8).bit_length() < pub.plaintext_bound_bits

    blob = one(pub, largest_encodable)
    assert p.decrypt(sec, blob) == pytest.approx(largest_encodable, rel=1e-12)


def test_модуль_пира_не_может_быть_сколь_угодно_длинным():
    """Отказ в обслуживании, а не стойкость.

    Сборка чужого ключа идёт под снятым GIL, поэтому `SIGINT` не доходит
    до процесса, пока она не вернётся. Модуль приезжает от пира по
    проводу.
    """
    huge = (2 ** 16384 + 1).to_bytes(2049, "big")

    with pytest.raises(ValueError):
        p.PublicKey.from_n(huge)


def test_отказ_по_длине_не_зависит_от_длины_входа():
    """Граница длины обязана стоять ДО всякой арифметики.

    Одного `pytest.raises` мало: отказ был и раньше, но `n²` считалось
    ДО проверки длины, и цена отказа росла по входу, который целиком
    задаёт нападающий. Замерено на прежнем коде: 0.009 с на 256 КБ,
    0.404 на 8 МБ, 1.92 на 32 МБ, **4.07 на 64 МБ** — и всё это с
    удержанным GIL, то есть интерпретатор не исполняет ничего, включая
    обработчики сигналов. Плюс двукратное усиление по памяти.

    Признак — ОТНОШЕНИЕ времён, а не абсолютное время: абсолютное
    зависит от машины, отношение нет. На прежнем коде оно было около
    450; сейчас отказ не смотрит на содержимое вовсе. Порог 10 оставляет
    сорокакратный запас и не ловит дрожание планировщика.
    """
    small = b"\xff" * (256 * 1024)
    large = b"\xff" * (64 * 1024 * 1024)

    def refusal_seconds(raw):
        best = None
        for _ in range(3):
            started = time.perf_counter()
            with pytest.raises(ValueError):
                p.PublicKey.from_n(raw)
            taken = time.perf_counter() - started
            best = taken if best is None else min(best, taken)
        return best

    on_small = refusal_seconds(small)
    on_large = refusal_seconds(large)

    assert on_large / max(on_small, 1e-9) < 10, (
        f"отказ на 64 МБ занял {on_large:.4f} с против {on_small:.4f} с на "
        f"256 КБ — значит длина проверяется после работы над содержимым"
    )


def test_пустая_сумма_отвергается(key):
    pub, _ = key

    with pytest.raises(ValueError):
        p.add_many(pub, [])


def test_слишком_длинный_ключ_отвергается():
    """Соседнее с границей значение — ловит сдвиг на единицу."""
    with pytest.raises(ValueError):
        p.generate_keypair(8193)


def test_очень_длинный_ключ_отвергается_БЫСТРО():
    """Граница сверху была введена только для ЧУЖОГО модуля.

    Свой оставался неограниченным: `generate_keypair(200000)` жил через
    одиннадцать секунд и `SIGINT` его не брал — тот же непрерываемый
    класс, что и снизу, закрытый с одной стороны.

    Отдельным процессом, как и нижняя граница: проверка на месте здесь
    не работает, потому что при отказе проверки вызов не возвращается —
    прогон мутаций это уже показал, повиснув на полчаса.
    """
    import subprocess
    import sys

    done = subprocess.run(
        [sys.executable, "-c", "import paillier; paillier.generate_keypair(200000)"],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert done.returncode != 0, "200000-битный ключ обязан отвергаться"
    assert "8192" in done.stderr, done.stderr[-400:]


@pytest.mark.parametrize("bits", [32, 256, 1024, 2047])
def test_короткий_ключ_отвергается(bits):
    """Границы не было вовсе.

    `generate_keypair(32)` возвращал 32-битный модуль, и сьют оставался
    зелёным целиком: круг верен, гомоморфность верна, проверки ключа
    довольны, а `n` раскладывается за микросекунды. Проверять надо
    отказ, потому что всё остальное тут в порядке.

    2047 стоит отдельно: соседнее с границей значение ловит сдвиг на
    единицу.
    """
    with pytest.raises(ValueError):
        p.generate_keypair(bits)


def test_короткий_ключ_отвергается_БЫСТРО():
    """Отказ обязан наступить ДО поиска простых.

    `generate_safe_prime` на восьми битах крутится вечно, а идёт он под
    снятым GIL, поэтому обработчик сигналов Python не исполняется:
    `generate_keypair(16)` не завершался ни по Ctrl-C, ни по внешнему
    `SIGINT`. Проверка на месте вызова этого не поймает — процесс просто
    не вернётся, — поэтому запуск отдельный, со сроком.

    Тест зелен и на коде, где проверка длины стоит ПОСЛЕ поиска простых:
    при 32 битах простые находятся мгновенно. Красным его делает 16.
    """
    import subprocess
    import sys

    done = subprocess.run(
        [sys.executable, "-c", "import paillier; paillier.generate_keypair(16)"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert done.returncode != 0, "16-битный ключ обязан отвергаться"
    assert "2048" in done.stderr, done.stderr[-400:]


def test_неверный_шифротекст_даёт_ошибку_а_не_панику(key):
    """`PanicException` наследует `BaseException`, а не `Exception`,
    поэтому паника проходит сквозь `except Exception` вызывающего и
    роняет процесс.

    Пустая сумма получала аккуратный отказ, а соседний вход того же
    происхождения паниковал на `.expect("oadd")`.
    """
    pub, _ = key
    good = one(pub, 1.0)

    with pytest.raises(ValueError):
        p.add_many(pub, [bytes(good), b"\x00"])


def test_сумма_больше_запаса_отвергается(key):
    """Поштучной проверки диапазона мало: переполняется СУММА.

    На 1024-битном ключе три законных значения по `2.29e299`
    складывались в `−4.57e299` — конечное правдоподобное число не того
    знака. Запас резервируется при шифровании, но держится он ровно до
    объявленного числа слагаемых, и это число обязано быть границей, а
    не пожеланием.
    """
    pub, _ = key
    terms = 2**20 + 1

    with pytest.raises(ValueError):
        p.add_many(pub, [b"\x01"] * terms)


def test_сумма_в_пределах_запаса_складывается_верно(key):
    """Обратная сторона: граница не должна мешать нормальной работе."""
    pub, sec = key

    blobs = list(p.encrypt_many(pub, [1e30, 1e30, -2e30]))

    assert p.decrypt(sec, p.add_many(pub, blobs)) == pytest.approx(0.0, abs=1e22)


# ---------------------------------------------------------------------
# Ключ пира: то, ради чего вывод `hs` на месте и существует
# ---------------------------------------------------------------------

def test_ключ_собирается_из_одного_модуля(key):
    """Шифрующий получает только `n` и выводит `hs` сам."""
    pub, sec = key

    peer = p.PublicKey.from_n(pub.modulus_bytes())
    blob = one(peer, 42.5)

    assert p.decrypt(sec, blob) == pytest.approx(42.5, abs=1e-7)


def test_разные_hs_под_одним_модулем_складываются(key):
    """Без этого вывод на месте не имеет права на существование:
    шифротексты двух сторон, выведших РАЗНЫЕ `hs`, обязаны складываться
    и расшифровываться верно."""
    pub, sec = key
    modulus = pub.modulus_bytes()

    first = p.PublicKey.from_n(modulus)
    second = p.PublicKey.from_n(modulus)

    blobs = [one(first, -4321.0), one(second, 9876.0)]
    total = p.decrypt(sec, p.add_many(first, blobs))

    assert total == pytest.approx(5555.0, abs=1e-6)


def test_чётный_модуль_отвергается():
    """Вход обязан быть ЗАКОННОЙ ДЛИНЫ, иначе тест доказывает не то.

    Прежде подавалось `2**64` — 65 бит. Такой модуль отвергается по
    длине, и тест оставался зелёным на коде, где проверки нечётности нет
    вовсе: он утверждал лишь «какой-нибудь ValueError». Различающий вход
    — чётный модуль, который по длине проходит.
    """
    even = (2 ** 2048).to_bytes(257, "big")

    with pytest.raises(ValueError, match="odd"):
        p.PublicKey.from_n(even)


def test_короткий_модуль_пира_отвергается():
    """`from_n` не проверял ЧУЖОЙ модуль ничем.

    Проверяем то же, что все: нечётность и длину — *partial public key
    validation*. Здесь судится, что проверка вообще ЗОВЁТСЯ из `from_n`;
    что именно она отвергает — в `tests/smooth_order_attack.rs`.
    """
    short = (2 ** 2000 + 1).to_bytes(251, "big")

    with pytest.raises(ValueError):
        p.PublicKey.from_n(short)


def test_сквозной_путь_ключа(key):
    """Сериализация → передача → шифрование → расшифровка.

    Ловит потерю модуля по дороге, которую послойные проверки не видят.
    """
    pub, sec = key

    wire = bytes(pub.modulus_bytes())
    assert len(wire) == math.ceil(BITS / 8)

    peer = p.PublicKey.from_n(wire)
    blobs = list(p.encrypt_many(peer, [1.0, 2.0, 3.0]))

    assert p.decrypt(sec, p.add_many(peer, blobs)) == pytest.approx(6.0, abs=1e-6)
