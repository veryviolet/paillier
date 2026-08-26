//! Сколько стоит постоянное по времени чтение строки таблицы.
//!
//! Кэш-канал оставался открытым не потому, что закрыть его дорого, а
//! потому, что цена была посчитана неверно. В докстринге стояло:
//! «читать всю строку на каждом окне — значит платить в шестнадцать
//! раз». Это смешивает две разные вещи. Умножение на 4096 битах
//! остаётся ОДНО; добавляется потоковое чтение `16 × 512` байт и сборка
//! числа из байтов.
//!
//! Здесь обе укладки живут рядом и меряются на одних и тех же `hs`,
//! `n²` и показателе:
//!
//! * **по индексу** — как было: `Vec<Vec<Integer>>`, запись берётся
//!   `row[digit]`, адрес обращения зависит от секретной цифры;
//! * **маской** — как стало: строка байтов читается целиком, нужная
//!   запись выбирается арифметической маской (`fast::pow_by_table`).
//!
//! Результаты сверяются на равенство: замер, у которого две ветви
//! считают разное, ничего не сравнивает.
//!
//! Запуск: `cargo bench --bench window_select`.

use paillier::fast::{build_window_table, pow_by_table, windows_for, windows_of, WINDOW_BITS};
use rug::Integer;
use std::time::Instant;

const ROUNDS: usize = 20;
const SERIES: usize = 5;

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    values[values.len() / 2]
}

/// Прежняя укладка: записи как `Integer`, выбор по индексу.
fn build_indexed(hs: &Integer, nn: &Integer, windows: usize) -> Vec<Vec<Integer>> {
    let width = 1usize << WINDOW_BITS;
    let mut table = Vec::with_capacity(windows);
    let mut base = hs.clone();
    for _ in 0..windows {
        let mut row = Vec::with_capacity(width);
        row.push(Integer::from(nn + 1u32));
        let mut value = base.clone();
        row.push(value.clone());
        for _ in 2..width {
            value = value * &base % nn;
            row.push(value.clone());
        }
        table.push(row);
        for _ in 0..WINDOW_BITS {
            base = base.clone().square() % nn;
        }
    }
    table
}

fn pow_indexed(table: &[Vec<Integer>], digits: &[u8], nn: &Integer) -> Integer {
    let mut result = Integer::from(1);
    for (window, digit) in digits.iter().enumerate() {
        result = result * &table[window][*digit as usize] % nn;
    }
    result
}

/// Числа нужной ДЛИНЫ: цена чтения и умножения зависит от длин, а не от
/// того, настоящий ли это ключ.
fn parameters(modulus_bits: u32) -> (Integer, Integer) {
    let mut n = Integer::from(1u32) << (modulus_bits - 1);
    n += 54321u32;
    n.set_bit(0, true);
    let nn = Integer::from(&n * &n);
    let hs = (Integer::from(1u32) << (modulus_bits + 7)) + 13579u32;
    (hs % &nn, nn)
}

fn main() {
    println!(
        "{:>7} {:>8} {:>14} {:>14} {:>10}",
        "бит n", "окон", "по индексу, мкс", "маской, мкс", "отношение"
    );
    for modulus_bits in [2048u32, 3072] {
        let (hs, nn) = parameters(modulus_bits);
        let exponent_bytes = (modulus_bits / 2 / 8) as usize;
        // Через ту же функцию, что и боевой путь. Здесь стояло
        // `exponent_bytes * 2` — формула для четырёхбитного окна, и
        // прогон строил таблицу в полтора раза больше боевой: 8.4 МБ
        // вместо 5.6 при 2048 битах, 18.9 вместо 12.6 при 3072. Второе
        // хуже: 18.9 МБ переходит границу L3 в 16 МБ — ровно ту,
        // которой обосновывается выбор шестёрки. То есть цена
        // постоянного чтения публиковалась снятой со структуры, которой
        // в библиотеке не бывает.
        let windows = windows_for(exponent_bytes);

        let indexed = build_indexed(&hs, &nn, windows);
        let masked = build_window_table(&hs, &nn, windows);

        let raw: Vec<u8> = (0..exponent_bytes).map(|i| (i * 37 + 11) as u8).collect();
        let digits = windows_of(&raw);

        assert_eq!(
            pow_indexed(&indexed, &digits, &nn),
            pow_by_table(&masked, &digits, &nn),
            "две укладки считают разное — сравнивать нечего"
        );

        let mut by_index = Vec::new();
        let mut by_mask = Vec::new();
        for _ in 0..SERIES {
            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ = pow_indexed(&indexed, &digits, &nn);
            }
            by_index.push(started.elapsed().as_secs_f64() / ROUNDS as f64 * 1e6);

            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ = pow_by_table(&masked, &digits, &nn);
            }
            by_mask.push(started.elapsed().as_secs_f64() / ROUNDS as f64 * 1e6);
        }

        let by_index = median(by_index);
        let by_mask = median(by_mask);
        println!(
            "{modulus_bits:>7} {windows:>8} {by_index:>14.1} {by_mask:>14.1} {:>10.2}",
            by_mask / by_index
        );
    }
}
