//! Таблица окон обязана давать РОВНО то же, что `pow_mod`.
//!
//! Приём чисто арифметический: он не меняет результат, только скорость.
//! Значит и проверять надо равенство результатов, а не круг — круг
//! зелен и на неверной таблице, если ошибка одинакова у шифрования и
//! расшифровки.
//!
//! Зовётся НАСТОЯЩИЙ код из `paillier::fast`. Прежняя редакция этого
//! файла собирала копию реализации по описанию и потому сверяла её сама
//! с собой; эталон здесь — `pow_mod` из GMP, независимая реализация
//! того же возведения.

use paillier::fast::{build_window_table, pow_by_table, windows_of};
use rug::integer::Order;
use rug::Integer;

/// Модуль, на котором считаем. Маленький — арифметика от размера не
/// зависит, а прогон должен быть быстрым.
fn fixture() -> (Integer, Integer) {
    let n = Integer::from(23u32) * 59u32;
    let nn = Integer::from(&n * &n);
    let hs = Integer::from(1234567u32) % nn.clone();
    (hs, nn)
}

#[test]
fn the_table_matches_pow_mod_on_every_two_byte_exponent() {
    // ИСЧЕРПЫВАЮЩЕ по двум байтам: 65536 показателей, все комбинации
    // цифр, включая нули в каждой позиции и цепочки нулей. Выборочные
    // значения пропустили бы ровно ту ошибку, ради которой тест и
    // написан, — пропуск или сдвиг окна.
    let (hs, nn) = fixture();
    let table = build_window_table(&hs, &nn, 4);

    for value in 0u32..=0xffff {
        let raw = [(value >> 8) as u8, value as u8];
        let expected = hs
            .clone()
            .pow_mod(&Integer::from(value), &nn)
            .expect("pow_mod");
        let got = pow_by_table(&table, &windows_of(&raw), &nn);
        assert_eq!(got, expected, "показатель {value}");
    }
}

#[test]
fn the_table_matches_at_a_production_length_exponent() {
    // Два байта не поймают ошибку, которая начинается за их пределами:
    // переполнение счётчика окон, обрыв таблицы, знаковое расширение.
    let (hs, nn) = fixture();
    let width = 128; // 1024 бита — как при модуле 2048
    let table = build_window_table(&hs, &nn, width * 2);

    for seed in 0u8..8 {
        let raw: Vec<u8> = (0..width)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
            .collect();
        let exponent = Integer::from_digits(&raw, Order::MsfBe);
        let expected = hs.clone().pow_mod(&exponent, &nn).expect("pow_mod");
        let got = pow_by_table(&table, &windows_of(&raw), &nn);
        assert_eq!(got, expected, "seed {seed}");
    }
}

#[test]
fn the_table_is_correct_with_multi_word_entries() {
    // На модуле `fixture` запись умещается в ОДНО 64-битное слово, и шаг
    // по строке равен единице. Ошибка в шаге — самая вероятная в
    // постоянном по времени чтении — на таком модуле неотличима от его
    // отсутствия: `entry * width` при `width = 1` совпадает с `entry`.
    //
    // Здесь `n²` занимает пять слов, поэтому шаг проверяется по-честному.
    let n = Integer::from(1u32) << 160u32;
    let n = n + 7u32;
    let nn = Integer::from(&n * &n);
    let hs = Integer::from(987654321u32);

    let table = build_window_table(&hs, &nn, 4);
    assert!(
        table.entry_width() >= 5,
        "запись должна быть многословной, а она {} слов",
        table.entry_width()
    );

    for value in 0u32..=0xffff {
        let raw = [(value >> 8) as u8, value as u8];
        let expected = hs
            .clone()
            .pow_mod(&Integer::from(value), &nn)
            .expect("pow_mod");
        let got = pow_by_table(&table, &windows_of(&raw), &nn);
        assert_eq!(got, expected, "показатель {value}");
    }
}

#[test]
fn a_zero_exponent_gives_one() {
    // Вырождение, на котором цикл не делает ни одного умножения.
    let (hs, nn) = fixture();
    let table = build_window_table(&hs, &nn, 4);

    let got = pow_by_table(&table, &windows_of(&[0u8, 0u8]), &nn);

    assert_eq!(got, 1);
}
