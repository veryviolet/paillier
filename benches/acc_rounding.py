"""Округляет кодировщик или усекает — различающим наблюдением.

Косвенно это видно по числам (усечение даёт ошибку в √3 больше), но
косвенное — не доказательство.

Проба: значение, у которого масштабированная величина имеет дробную
часть 0.7. Усечение к нулю отбросит её, округление к ближайшему —
добавит единицу. Ответы расходятся, и по ответу видно правило.

Дробная часть именно 0.7, а не 0.5. Ровная половина кажется самой
показательной пробой, но `1.0000005` в двоичном float не представимо
точно, и `value·scale` оказывается чуть меньше или чуть больше половины
— то есть проба на ничью превращается в пробу на то, куда легла ошибка
представления. При 0.7 ничьей нет вовсе.

Знак важен не меньше величины. Усечение к нулю смещает вниз ПО МОДУЛЮ с
обеих сторон, то есть даёт снос, противоположный знаку числа; на
симметричном входе сносы гасятся и остаётся `√k`, а на знакопостоянном —
накапливаются линейно.

Запуск: `python benches/acc_rounding.py ours` либо `... heu`.
"""
import math
import sys


def what_was_done(value, scale, decoded):
    """Какое правило объясняет ответ: усечение или округление."""
    scaled = value * scale
    toward_zero = math.trunc(scaled)
    to_nearest = math.floor(scaled + 0.5) if scaled > 0 else math.ceil(scaled - 0.5)
    got = round(decoded * scale)

    if toward_zero == to_nearest:
        return f"проба не различает ({got})"
    if got == toward_zero:
        return "усечение к нулю"
    if got == to_nearest:
        return "к ближайшему"
    return f"ни то ни другое: {got}"


def probes_for(scale):
    """Значения, у которых `value·scale` имеет дробную часть 0.7."""
    step = 0.7 / scale
    return [1 + step, -(1 + step), 2 + step, -(2 + step)]


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "ours"
    print(f"{'вход':>18} {'обратно':>18} {'что сделано':>26}")

    if which == "heu":
        from heu import phe as hp

        scale = 10 ** 6
        kit = hp.setup(hp.SchemaType.ZPaillier, 2048)
        enc, dec = kit.encryptor(), kit.decryptor()
        encoder = hp.FloatEncoder(hp.SchemaType.ZPaillier, scale)
        for value in probes_for(scale):
            back = encoder.decode(dec.decrypt(enc.encrypt(encoder.encode(value))))
            print(f"{value:>18.9f} {back:>18.9f} {what_was_done(value, scale, back):>26}")
    else:
        import paillier as p

        # Масштаб зашит в библиотеку, поэтому пробы берутся под него.
        scale = 10 ** 8
        pub, sec = p.generate_keypair(2048)
        for value in probes_for(scale):
            back = p.decrypt(sec, bytes(p.encrypt_many(pub, [value])[0]))
            print(f"{value:>18.11f} {back:>18.11f} {what_was_done(value, scale, back):>26}")


if __name__ == "__main__":
    main()
