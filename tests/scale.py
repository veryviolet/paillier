"""Масштаб кодирования: настраиваемый, и разойтись им нечем.

Масштаб — свойство ШИФРОТЕКСТА, а не настройки вызова. Причина в том,
что несовпадение масштабов даёт не отказ, а правдоподобное неверное
число: те же коды, та же длина, тот же вид — только результат меньше в
`10^Δ` раз. Проверки здесь стерегут именно это.

Отдельно про пассивную сторону: она собирает чужой ключ из одного `n`
(`PublicKey.from_n`), а в `n` масштаба нет. Значит при настройке «сбоку»
пир взял бы умолчание и молча разошёлся с владельцем ключа. Поэтому
масштаб едет в блобе, и тест `test_пир_читает_масштаб_из_блоба` — про
это, а не про сериализацию.
"""
import pytest

import paillier as p

BITS = 2048


@pytest.fixture(scope="module")
def key():
    return p.generate_keypair(BITS)


def one(pub, value, **kw):
    return bytes(list(p.encrypt_many(pub, [value], **kw))[0])


@pytest.mark.parametrize("pow10", [0, 3, 8, 12, 15, 18])
def test_круг_на_каждом_масштабе(key, pow10):
    """Ошибка кодирования равна `1/(2·10^e)` — по ней и судим.

    Сравнивать с фиксированным допуском нельзя: при `e = 0` кодируется
    только целое, и `1.5` вернётся как `2.0`. Допуск обязан следовать за
    масштабом, иначе тест либо ложно красный внизу, либо слепой наверху.
    """
    pub, sec = key
    value = 1.5

    back = p.decrypt(sec, one(pub, value, scale_pow10=pow10))

    assert abs(back - value) <= 1.0 / (2 * 10 ** pow10)


def test_расшифровка_берёт_масштаб_из_блоба(key):
    """Главная проверка файла.

    Если бы `decrypt` брал масштаб из умолчания, значение,
    зашифрованное с `1e12`, вернулось бы МЕНЬШЕ В ДЕСЯТЬ ТЫСЯЧ РАЗ —
    конечным, правдоподобным, без единого признака ошибки.
    """
    pub, sec = key
    value = 1234.5678

    back = p.decrypt(sec, one(pub, value, scale_pow10=12))

    assert back == pytest.approx(value, abs=1e-9)


def test_пир_читает_масштаб_из_блоба(key):
    """Пир собирает ключ из одного `n`, масштаба он не знает.

    Это не про сериализацию, а про то, что договариваться о масштабе
    сторонам не нужно вовсе.
    """
    pub, sec = key
    peer = p.PublicKey.from_n(pub.modulus_bytes())

    back = p.decrypt(sec, one(peer, -7.25, scale_pow10=15))

    assert back == pytest.approx(-7.25, abs=1e-12)


def test_сумма_разных_масштабов_отвергается(key):
    """Отказ, а не приведение к общему масштабу.

    Привести можно только умножением открытого текста, а он зашифрован.
    Значит остаётся либо отказать, либо вернуть бессмыслицу.
    """
    pub, _ = key
    blobs = [one(pub, 1.0, scale_pow10=8), one(pub, 2.0, scale_pow10=12)]

    with pytest.raises(ValueError, match="scale"):
        p.add_many(pub, blobs)


def test_сумма_сохраняет_масштаб(key):
    """Иначе отказ выше был бы бесполезен: сумма пачки на `1e12` должна
    складываться со следующей такой же."""
    pub, sec = key
    blobs = [one(pub, v, scale_pow10=12) for v in (1.5, 2.25, -0.75)]

    total = p.add_many(pub, blobs)

    assert p.decrypt(sec, total) == pytest.approx(3.0, abs=1e-9)
    # И результат снова складывается — масштаб уцелел в блобе.
    assert p.decrypt(sec, p.add_many(pub, [bytes(total), blobs[0]])) == (
        pytest.approx(4.5, abs=1e-9)
    )


@pytest.mark.parametrize("pow10", [19, 200, 255])
def test_слишком_большой_масштаб_отвергается(key, pow10):
    pub, _ = key

    with pytest.raises(ValueError, match="scale exponent"):
        p.encrypt_many(pub, [1.0], scale_pow10=pow10)


def test_блоб_с_чужим_показателем_отвергается_при_расшифровке(key):
    """Показатель приезжает по проводу, значит он вход, а не константа."""
    pub, sec = key
    blob = bytearray(one(pub, 1.0))
    blob[0] = 200

    with pytest.raises(ValueError, match="scale exponent"):
        p.decrypt(sec, bytes(blob))


def test_пустой_блоб_отвергается(key):
    _, sec = key

    with pytest.raises(ValueError):
        p.decrypt(sec, b"")


def test_масштаб_действительно_улучшает_сумму(key):
    """Ради чего настройка и заводилась — с числом, а не на словах.

    Вход НЕОТРИЦАТЕЛЬНЫЙ: на симметричном сносы разных знаков гасятся, и
    выигрыш масштаба виден куда хуже.

    Нижняя проверка обязательна: без неё тест зеленел бы и на паре
    нулей, ведь «одно меньше другого в пятьдесят раз» верно и для двух
    нулей... точнее, деление упало бы, но на двух ОЧЕНЬ малых величинах
    отношение стало бы шумом. Требуем, чтобы у `1e8` ошибка была
    заметной.
    """
    from fractions import Fraction
    import random

    pub, sec = key
    random.seed(20260826)
    values = [random.uniform(0.0, 1000.0) for _ in range(10_000)]
    exact = sum((Fraction(v) for v in values), Fraction(0))

    def error(pow10):
        blobs = [bytes(b) for b in p.encrypt_many(pub, values, scale_pow10=pow10)]
        got = p.decrypt(sec, p.add_many(pub, blobs))
        return float(abs(Fraction(got) - exact))

    coarse = error(8)
    fine = error(12)

    assert coarse > 1e-8, f"при 1e8 ошибка {coarse:.2e} — измерять нечего"
    assert fine * 50 < coarse, f"1e12 дал {fine:.2e} против {coarse:.2e} у 1e8"
