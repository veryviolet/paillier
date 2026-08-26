//! Сколько стоит безопасное к показателю возведение — на наших числах.
//!
//! Расшифровка у нас медленнее, чем у `heu`, и это надо объяснять
//! измерением, а не памятью. Отличие по существу одно: два возведения
//! в `secret::decrypt` идут через `mpz_powm_sec`, а не `mpz_powm`.
//! `mpz_powm` — оконное возведение с обращением к таблице ПО БИТАМ
//! показателя, то есть по битам `λ`, долговременного секрета ключа;
//! `mpz_powm_sec` читает всю таблицу на каждом шаге.
//!
//! Меряется ровно эта разница и ничего больше: те же основание,
//! показатель и модуль, что в компонентах китайской теоремы, —
//! показатель `p−1` длиной `|n|/2`, модуль `p²` длиной `|n|`. Остальные
//! шаги расшифровки у обоих вариантов одинаковы и в замер не входят.
//!
//! Запуск: `cargo bench --bench secure_pow`.

use rug::Integer;
use std::time::Instant;

/// Повторов на точку. Одно возведение при 2048 битах — около
/// миллисекунды, так что сотни хватает, а разброс между прогонами
/// виден по трём независимым сериям.
const ROUNDS: usize = 100;
const SERIES: usize = 3;

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    values[values.len() / 2]
}

/// Числа нужной ДЛИНЫ, а не настоящий ключ: цена возведения зависит от
/// длин, а не от простоты. Порождение безопасных простых заняло бы
/// секунды и ничего к замеру не добавило бы.
fn parameters(modulus_bits: u32) -> (Integer, Integer, Integer) {
    let half = modulus_bits / 2;
    let mut p = Integer::from(1u32) << (half - 1);
    p += 12345u32;
    p.set_bit(0, true);
    let p_square = Integer::from(&p * &p);
    let exponent = Integer::from(&p - 1u32);
    let base = (Integer::from(1u32) << (modulus_bits - 3)) + 6789u32;
    (base % &p_square, exponent, p_square)
}

fn main() {
    println!(
        "{:>7} {:>12} {:>12} {:>10}",
        "бит n", "powm, мкс", "powm_sec", "отношение"
    );
    for modulus_bits in [2048u32, 3072] {
        let (base, exponent, modulus) = parameters(modulus_bits);

        let mut plain = Vec::new();
        let mut secure = Vec::new();
        for _ in 0..SERIES {
            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ = base.clone().pow_mod(&exponent, &modulus).unwrap();
            }
            plain.push(started.elapsed().as_secs_f64() / ROUNDS as f64 * 1e6);

            let started = Instant::now();
            for _ in 0..ROUNDS {
                let _ = base.clone().secure_pow_mod(&exponent, &modulus);
            }
            secure.push(started.elapsed().as_secs_f64() / ROUNDS as f64 * 1e6);
        }

        let plain = median(plain);
        let secure = median(secure);
        println!(
            "{modulus_bits:>7} {plain:>12.1} {secure:>12.1} {:>10.2}",
            secure / plain
        );
    }
}
