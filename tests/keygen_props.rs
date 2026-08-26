//! Порог Ферма: единственная константа, которая уже дважды была
//! неверной и до этого файла не была прикрыта ничем.
//!
//! Проверяется не значение константы, а её следствие: ключ, который
//! проверка отвергает, ДЕЙСТВИТЕЛЬНО раскладывается методом Ферма —
//! прямо в тесте, а не по оценке. Число шагов при `|p−q| = |p|/2 + k`
//! равно `≈ (p−q)²/(8√n) = 2^(|p|+2k)/2^(|p|+3) = 2^(2k−3)` и от
//! размера ключа не зависит вовсе: при `k = 8` это `2^13` шагов что при
//! 512-битных простых, что при 1536-битных. Именно поэтому редакция с
//! порогом `|p|/2 + 8` принимала ключ, раскладываемый за тысячи шагов.
//!
//! Второй тест — обратная сторона: штатный ключ из двух независимых
//! безопасных простых обязан проходить. Без него порог можно «починить»
//! до полного запрета, и первый тест останется зелёным.

use paillier::keys::validate_private;
use rand::Rng;
use rug::integer::{IsPrime, Order};
use rug::Integer;

/// Половина нижней границы модуля: короче нельзя, и `validate_private`
/// отвечает `ModulusTooShort` прежде, чем дойдёт до порога Ферма.
const PRIME_BITS: u32 = 1024;

fn random_odd(bits: u32) -> Integer {
    let mut rng = rand::thread_rng();
    let width = (bits / 8) as usize;
    let mut raw = vec![0u8; width];
    rng.fill(&mut raw[..]);
    raw[0] |= 0x80;
    let last = width - 1;
    raw[last] |= 1;
    Integer::from_digits(&raw, Order::MsfBe)
}

/// Ближайшее безопасное простое не ниже `start`.
fn safe_prime_at_or_above(start: &Integer) -> Integer {
    let mut c = start.clone();
    loop {
        c.next_prime_mut();
        let half = Integer::from(&c - 1u32) / 2u32;
        if half.is_probably_prime(40) != IsPrime::No {
            return c;
        }
    }
}

/// Метод Ферма. Возвращает делитель и число сделанных шагов.
fn fermat(n: &Integer, budget: u64) -> Option<(Integer, u64)> {
    let mut a = n.clone().sqrt();
    if Integer::from(&a * &a) < *n {
        a += 1;
    }
    for step in 0..budget {
        let b2 = Integer::from(&a * &a) - n;
        if b2.is_perfect_square() {
            let b = b2.sqrt();
            return Some((Integer::from(&a - &b), step));
        }
        a += 1;
    }
    None
}

#[test]
fn отвергнутый_ключ_действительно_раскладывается_методом_ферма() {
    let p = safe_prime_at_or_above(&random_odd(PRIME_BITS));

    // Целимся на границу ПРЕЖНЕЙ, неверной редакции: |p|/2 + 8 бит.
    let threshold_bits = PRIME_BITS / 2 + 8; // 264
    let gap = Integer::from(1) << (threshold_bits - 1); // 2^263, ровно 264 бита
    let margin = Integer::from(1) << 24; // с запасом на шаг поиска простого
    let target = Integer::from(&p - &gap) - margin;
    let q = safe_prime_at_or_above(&target);

    let diff = Integer::from(&p - &q).abs();
    println!("|p|      = {}", p.significant_bits());
    println!("|q|      = {}", q.significant_bits());
    println!(
        "|p−q|    = {} (прежний порог {}, нынешний {})",
        diff.significant_bits(),
        threshold_bits,
        PRIME_BITS - 100,
    );

    // 1. ТЕПЕРЬ такой ключ обязан отвергаться.
    let verdict = validate_private(&p, &q);
    println!("validate_private: {verdict:?}");
    assert_eq!(
        verdict,
        Err(paillier::keys::KeyError::PrimesTooClose),
        "ключ, раскладываемый Ферма за тысячи шагов, обязан отвергаться",
    );

    // 2. И раскладывается методом Ферма за считанные тысячи шагов.
    let n = Integer::from(&p * &q);
    let started = std::time::Instant::now();
    let (factor, steps) = fermat(&n, 100_000_000).expect("Ферма обязан справиться");
    println!(
        "и он действительно раскладывается за {} шагов ({:?}) — потому отказ и верен",
        steps,
        started.elapsed(),
    );
    assert!(factor == p || factor == q);
}

/// Безопасное простое, ближайшее к `p − 2^gap_bits`.
fn safe_prime_at_gap(p: &Integer, gap_bits: u32) -> Integer {
    let gap = Integer::from(1) << (gap_bits - 1);
    let margin = Integer::from(1) << 24;
    safe_prime_at_or_above(&(Integer::from(p - &gap) - margin))
}

#[test]
fn порог_закреплён_числом_с_обеих_сторон() {
    // Два теста в этом файле допускали целую полосу значений порога:
    // при `SLACK = 247` оба оставались зелёными, а принятый ими ключ
    // раскладывался Ферма за 24 тысячи шагов. Здесь порог зажат с обеих
    // сторон, и полосы не остаётся.
    let threshold = PRIME_BITS - 100;
    let p = safe_prime_at_or_above(&random_odd(PRIME_BITS));

    let just_below = safe_prime_at_gap(&p, threshold - 1);
    let just_above = safe_prime_at_gap(&p, threshold + 1);

    let below_bits = Integer::from(&p - &just_below).abs().significant_bits();
    let above_bits = Integer::from(&p - &just_above).abs().significant_bits();
    println!("порог {threshold}: снизу {below_bits}, сверху {above_bits}");
    assert!(below_bits < threshold, "нижний образец обязан быть ниже порога");
    assert!(above_bits >= threshold, "верхний образец обязан быть не ниже");

    assert_eq!(
        validate_private(&p, &just_below),
        Err(paillier::keys::KeyError::PrimesTooClose),
        "разность на бит ниже порога обязана отвергаться",
    );
    assert!(
        validate_private(&p, &just_above).is_ok(),
        "разность на бит выше порога обязана приниматься",
    );
}

// Теста «generate_keypair зовёт проверку ключа» здесь БОЛЬШЕ НЕТ, и это
// не потеря покрытия.
//
// Он был структурным — читал `src/lib.rs` и искал вызов в тексте. Такой
// тест проходит насквозь, если вызов заменить комментарием с тем же
// текстом (проверено: ключ собирается без единой проверки простых, а
// сьют показывает 42 из 42), и краснеет, если вызов честно вынести в
// помощника. То есть ловил не то и наказывал верное.
//
// Проводку теперь стережёт компилятор: `validate_private` возвращает
// `keys::Validated`, собрать его вне модуля `keys` нельзя, а `SecretKey`
// без него не строится. Пропуск проверки перестал компилироваться.

#[test]
fn у_штатного_ключа_разность_почти_полной_длины() {
    // Для контраста: два независимых безопасных простых.
    let p = safe_prime_at_or_above(&random_odd(PRIME_BITS));
    let q = safe_prime_at_or_above(&random_odd(PRIME_BITS));
    let diff = Integer::from(&p - &q).abs();
    println!(
        "штатный ключ: |p−q| = {} при |p| = {} (порог {})",
        diff.significant_bits(),
        PRIME_BITS,
        PRIME_BITS - 100,
    );
    assert!(validate_private(&p, &q).is_ok());
}
