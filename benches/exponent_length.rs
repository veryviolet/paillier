//! Что даёт сокращение показателя — замером, а не арифметикой в уме.
//!
//! В `docs/short-exponent-security.md` стояло: показатель `|n|/2`
//! избыточен вчетверо, и сокращение до 256 бит подняло бы однопоточное
//! шифрование «примерно с 683 до 2600 эл/с». Число не выведено ни из
//! чего: линейность по числу окон замерена, но постоянные накладные —
//! кодирование, `1 + m·n`, умножение, сериализация — из расчёта выпали,
//! а они и решают, во что упирается результат после сокращения.
//!
//! Здесь меряется ровно то, что от длины показателя зависит: время
//! `pow_by_table` при 256 окнах (показатель 1024 бита, как сейчас) и при
//! 64 (256 бит). Всё остальное в шифровании от длины показателя не
//! зависит, поэтому полное время получается сложением с постоянной
//! частью, которую меряет `benches/bench_rust.py`.
//!
//! Запуск: `cargo bench --bench exponent_length`.

use paillier::fast::{build_window_table, pow_by_table, windows_for, windows_of};
use rug::Integer;
use std::time::Instant;

const ROUNDS: usize = 20;
const SERIES: usize = 5;

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    values[values.len() / 2]
}

fn parameters(modulus_bits: u32) -> (Integer, Integer) {
    let mut n = Integer::from(1u32) << (modulus_bits - 1);
    n += 54321u32;
    n.set_bit(0, true);
    let nn = Integer::from(&n * &n);
    let hs = (Integer::from(1u32) << (modulus_bits + 7)) + 13579u32;
    (hs % &nn, nn)
}

fn main() {
    let modulus_bits = 2048u32;
    let (hs, nn) = parameters(modulus_bits);

    println!("модуль {modulus_bits} бит");
    println!(
        "{:>16} {:>7} {:>14}",
        "показатель, бит", "окон", "pow_by_table"
    );

    let mut measured = Vec::new();
    for exponent_bits in [1024usize, 512, 256] {
        let exponent_bytes = exponent_bits / 8;
        // Через ту же функцию, что и боевой путь. Здесь стояло
        // `exponent_bytes * 2` — формула, верная только при
        // `WINDOW_BITS = 4`; при шести она печатала вдвое больше окон,
        // чем считалось на деле.
        let windows = windows_for(exponent_bytes);
        let table = build_window_table(&hs, &nn, windows);
        let raw: Vec<u8> = (0..exponent_bytes).map(|i| (i * 37 + 11) as u8).collect();
        let digits = windows_of(&raw);

        let mut taken = Vec::new();
        for _ in 0..SERIES {
            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ = pow_by_table(&table, &digits, &nn);
            }
            taken.push(started.elapsed().as_secs_f64() / ROUNDS as f64 * 1e6);
        }
        let taken = median(taken);
        println!("{exponent_bits:>16} {windows:>7} {taken:>11.1} мкс");
        measured.push((exponent_bits, taken));
    }

    // Постоянная часть шифрования не зависит от длины показателя, но
    // именно она задаёт потолок после сокращения. Её значение меряет
    // `benches/bench_rust.py` (полное последовательное шифрование минус
    // `pow_by_table` при 1024-битном показателе) и передаёт сюда числом,
    // а не догадкой.
    println!(
        "\nполное время = pow_by_table + постоянная часть;\n\
         постоянную часть мерить здесь нечем — она в `bench_rust.py`."
    );
    let full = measured[0].1;
    for (bits, taken) in &measured {
        println!(
            "{bits:>5} бит: доля возведения от нынешнего полного возведения — {:.2}",
            taken / full
        );
    }
}
