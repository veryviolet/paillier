//! Сколько стоит умножение по модулю `n²` — и стоит ли Монтгомери.
//!
//! Прогон отдельный, потому что решение по Монтгомери принималось
//! замером ТОЛЬКО на шифровании, и это была ошибка: там всё съедала
//! таблица окон. Сложение — другая операция с другим профилем, и
//! переносить вывод с одной на другую нельзя.
//!
//! Запуск: `cargo test --release --bench modmul -- --nocapture`.

use rug::Integer;
use std::time::Instant;

const ROUNDS: usize = 20_000;

/// REDC поверх `rug::Integer` — ровно тот, что был снят.
struct Montgomery {
    modulus: Integer,
    bits: u32,
    inverse: Integer,
    r_squared: Integer,
}

impl Montgomery {
    fn new(modulus: &Integer) -> Self {
        let bits = (modulus.significant_bits() + 63) / 64 * 64;
        let r = Integer::from(1) << bits;
        let inverse = Integer::from(&r) - modulus.clone().invert(&r).expect("нечётный модуль");
        let r_squared = (Integer::from(1) << (2 * bits)) % modulus;
        Self { modulus: modulus.clone(), bits, inverse, r_squared }
    }

    fn reduce(&self, value: Integer) -> Integer {
        let low = value.clone().keep_bits(self.bits);
        let m = (low * &self.inverse).keep_bits(self.bits);
        let result = (value + m * &self.modulus) >> self.bits;
        if result >= self.modulus { result - &self.modulus } else { result }
    }

    fn multiply(&self, left: &Integer, right: &Integer) -> Integer {
        self.reduce(Integer::from(left * right))
    }

    fn enter(&self, value: &Integer) -> Integer {
        self.reduce(Integer::from(value * &self.r_squared))
    }
}

fn modulus_of(bits: u32) -> Integer {
    let mut n = (Integer::from(1) << (bits / 2)) + 1u32;
    n.next_prime_mut();
    let mut q = (Integer::from(1) << (bits / 2)) + 12345u32;
    q.next_prime_mut();
    Integer::from(&n * &q)
}

fn main() {
    for key_bits in [2048u32, 3072] {
        let n = modulus_of(key_bits);
        let nn = Integer::from(&n * &n);
        println!("\n=== модуль ключа {key_bits} бит, n² = {} бит ===", nn.significant_bits());

        let a = Integer::from(&nn / 3u32) + 7u32;
        let b = Integer::from(&nn / 5u32) + 11u32;

        let started = Instant::now();
        let mut acc = a.clone();
        for _ in 0..ROUNDS {
            acc = acc * &b % &nn;
        }
        let plain = started.elapsed();
        println!(
            "обычное  a·b mod n²   {:8.3?}  {:6.2} мкс/оп",
            plain,
            plain.as_secs_f64() * 1e6 / ROUNDS as f64,
        );

        let space = Montgomery::new(&nn);
        let bm = space.enter(&b);
        let started = Instant::now();
        let mut acc_m = space.enter(&a);
        for _ in 0..ROUNDS {
            acc_m = space.multiply(&acc_m, &bm);
        }
        let mont = started.elapsed();
        println!(
            "Монтгомери            {:8.3?}  {:6.2} мкс/оп   отношение {:.2}",
            mont,
            mont.as_secs_f64() * 1e6 / ROUNDS as f64,
            plain.as_secs_f64() / mont.as_secs_f64(),
        );
        // Разбор байт — третий подозреваемый, и его надо мерить, а не
        // называть. `add_many` получает шифротексты списком `bytes`, и
        // каждый разбирается в `Integer` заново.
        let raw = a.to_digits::<u8>(rug::integer::Order::MsfBe);
        let started = Instant::now();
        let mut guard = Integer::from(0);
        for _ in 0..ROUNDS {
            guard += Integer::from_digits(&raw, rug::integer::Order::MsfBe)
                .significant_bits();
        }
        let parse = started.elapsed();
        println!(
            "разбор {} байт в Integer  {:8.3?}  {:6.2} мкс/оп",
            raw.len(),
            parse,
            parse.as_secs_f64() * 1e6 / ROUNDS as f64,
        );
        println!(
            "  итого разбор + умножение   {:6.2} мкс/оп",
            (parse.as_secs_f64() + plain.as_secs_f64()) * 1e6 / ROUNDS as f64,
        );

        // Точная копия цикла `add_many`: свои байты у каждого
        // слагаемого, разбор и умножение — как в бою.
        //
        // Здесь печаталось «(в add_many замерено 85)» — литерал из
        // замера, которого давно нет: 85 мкс было до перехода на
        // короткий показатель, а `benches/measure.py` даёт 6.9. То есть
        // прогон, написанный ради объяснения разрыва, продолжал
        // печатать разрыв, которого уже нет, — и печатал бы вечно,
        // потому что литерал не пересчитывается ни от чего.
        //
        // Сравнивать надо со строкой этого же вывода, а не с числом из
        // памяти.
        let blobs: Vec<Vec<u8>> = (0..10_000u32)
            .map(|i| {
                (Integer::from(&nn / 7u32) + i)
                    .to_digits::<u8>(rug::integer::Order::MsfBe)
            })
            .collect();
        let started = Instant::now();
        let mut total = Integer::from(1);
        for blob in &blobs {
            let value = Integer::from_digits(blob, rug::integer::Order::MsfBe);
            total = total * value % &nn;
        }
        let replica = started.elapsed();
        println!(
            "копия цикла add_many      {:8.3?}  {:6.2} мкс/слагаемое",
            replica,
            replica.as_secs_f64() * 1e6 / blobs.len() as f64,
        );

        // Чтобы оптимизатор не выбросил циклы.
        assert!(acc > 0 && acc_m > 0 && guard > 0 && total > 0);
    }
}
