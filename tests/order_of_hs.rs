//! Какие порядки может иметь `hs` при безопасных простых.
//!
//! На этом держится стойкость короткого показателя: гладкий порядок
//! делает Полига–Хеллмана дешёвым, и запас `2^(|r|/2)` перестаёт что-либо
//! значить (`docs/short-exponent-security.md`).
//!
//! # Почему множество порядков ровно `{2, 2p′, 2q′, 2p′q′}`
//!
//! Это следствие, а не наблюдение. При безопасных `p = 2p′+1` и
//! `q = 2q′+1` группа `Z*_n ≅ Z_{2p′} × Z_{2q′}`, а `hs = h^n`. В
//! `Z*_{n²} ≅ Z*_{p²} × Z*_{q²}` возведение в степень `n = pq`
//! оставляет в компонентах порядки, делящие `2p′` и `2q′`, откуда
//! `ord(hs) | lcm(2p′, 2q′) = 2p′q′`. Делители `2p′q′` — это
//! `1, 2, p′, q′, 2p′, 2q′, p′q′, 2p′q′`; нечётные отпадают, потому что
//! `h = −x²` имеет чётный порядок, а `1` и `2` отсеивает
//! `DegenerateHs`.
//!
//! Довод не зависит от длины ключа. Поэтому здесь два теста, а не один:
//! исчерпывающий на ИГРУШЕЧНОМ ключе, где перебор всех `x` возможен, и
//! выборочный на настоящем, где он невозможен ни при какой машине.
//!
//! # Что здесь исправляется
//!
//! В документе стояло: «полный перебор всех `x` на пяти НАСТОЯЩИХ
//! ключах дал порядки ровно из `{2, 2p′, 2q′, 2p′q′}`». Полный перебор
//! `Z*_n` при `|n| ≥ 2048` невозможен, и никакого артефакта за этой
//! фразой в репозитории не было — как и за «200 из 200» и «400 из 400»
//! в соседних абзацах. Утверждение было верным, а свидетельство —
//! выдуманным.

use paillier::keys::{derive_h, derive_hs, KeyError};
use paillier::primes::safe_prime;
use rug::Integer;

/// Порядок `value` в `Z*_{n²}`, если известно разложение `λ = 2·p′·q′`.
///
/// Спуск по делителям: начинаем с `λ` и делим на каждый простой,
/// пока степень остаётся нейтральной.
fn order_of(value: &Integer, nn: &Integer, p_half: &Integer, q_half: &Integer) -> Integer {
    let mut order = Integer::from(2u32) * p_half * q_half;
    for divisor in [Integer::from(2u32), p_half.clone(), q_half.clone()] {
        loop {
            let reduced = Integer::from(&order / &divisor);
            if Integer::from(&order % &divisor) != 0
                || value.clone().pow_mod(&reduced, nn).expect("pow_mod") != 1
            {
                break;
            }
            order = reduced;
        }
    }
    order
}

/// `p = 2·11+1 = 23`, `q = 2·29+1 = 59`: `n = 1357`, в `Z*_n` ровно
/// `φ(n) = 1276` элементов, и перебор ЧЕСТНО полный.
///
/// Пара взята та же, что в `tests/degenerate_x.rs`, и это существенно.
/// Здесь стояло `q = 47` — и на нём `q − 1 = 2·23`, то есть `p` делит
/// `λ`, `gcd(λ, n) = 23`, `µ = λ⁻¹ mod n` не существует и схема не
/// работает вовсе. Хуже: отображение `h ↦ h^n mod n²` перестаёт быть
/// инъективным, а это ЦЕНТРАЛЬНЫЙ шаг довода выше. Утверждение
/// `ord(hs) | 2p′q′` держалось и там, но отказы, которые тест считает,
/// были на девять десятых артефактом сломанной фикстуры, а не
/// поведением схемы.
///
/// Соседний файл от этой пары уже уходил и записал почему. Я вернул её
/// обратно, не прочитав, — а свидетельство, снятое на негодной
/// фикстуре, свидетельствует о фикстуре.
#[test]
fn исчерпывающе_на_игрушечном_ключе() {
    let (p, q) = (Integer::from(23u32), Integer::from(59u32));
    let p_half = Integer::from(11u32);
    let q_half = Integer::from(29u32);
    let n = Integer::from(&p * &q);
    let nn = Integer::from(&n * &n);

    let allowed = [
        Integer::from(2u32) * &p_half,
        Integer::from(2u32) * &q_half,
        Integer::from(2u32) * &p_half * &q_half,
    ];

    let mut checked = 0usize;
    let mut rejected = 0usize;
    let mut x = Integer::from(2u32);
    let top = Integer::from(&n - 2u32);
    while x <= top {
        match derive_h(&x, &n).and_then(|h| derive_hs(&h, &n)) {
            Ok(hs) => {
                let order = order_of(&hs, &nn, &p_half, &q_half);
                assert!(
                    allowed.contains(&order),
                    "x = {x} дал порядок {order}, которого в множестве нет"
                );
                checked += 1;
            }
            // `BadX` — не взаимно просто; `DegenerateHs` — порядок ≤ 2,
            // ровно то вырождение, которое проверка и обязана ловить.
            Err(KeyError::BadX) | Err(KeyError::DegenerateHs) => rejected += 1,
            Err(other) => panic!("неожиданная ошибка на x = {x}: {other:?}"),
        }
        x += 1u32;
    }

    // Утверждение об отсутствии зеленеет на пустоте: если бы `derive_h`
    // отвергала всё подряд, цикл не проверил бы ни одного порядка и тест
    // всё равно прошёл бы. Поэтому два счётчика и обе стороны.
    //
    // Порог не выдуман: перебор идёт по `x ∈ [2, n−2]`, отвергаются
    // кратные `p` или `q` (это `p + q − 2` значений) плюс те, где
    // `h = −1`. На годной фикстуре вырожденных ровно два, поэтому
    // отвергается около шести процентов. Восемьдесят — запас под
    // изменение `derive_h`, который всё ещё падает, если она начнёт
    // отвергать всё подряд.
    let total = checked + rejected;
    let expected: usize = (Integer::from(&n - 3u32)).to_usize().expect("влезает");
    assert_eq!(total, expected, "перебор пропустил часть диапазона");
    assert!(
        checked * 100 >= total * 80,
        "принято {checked} из {total} — проверка порядков почти ничего не увидела"
    );
    assert!(rejected > 0, "ни одно значение не отвергнуто — это подозрительно");
}

/// На настоящих длинах перебор невозможен, поэтому здесь выборка — и
/// сказано, какая именно.
#[test]
fn выборочно_на_ключах_настоящей_конструкции() {
    // 256-битные простые: конструкция та же, что при 1024, а прогон
    // укладывается в секунды. Довод выше от длины не зависит, и это
    // проверяется отдельным ключом боевой длины ниже.
    const KEYS: usize = 12;
    let mut full = 0usize;
    for _ in 0..KEYS {
        let p = safe_prime(256);
        let q = safe_prime(256);
        if p == q {
            continue;
        }
        let p_half = Integer::from(&p - 1u32) / 2u32;
        let q_half = Integer::from(&q - 1u32) / 2u32;
        let n = Integer::from(&p * &q);
        let nn = Integer::from(&n * &n);

        let mut x = Integer::from(3u32);
        let hs = loop {
            match derive_h(&x, &n).and_then(|h| derive_hs(&h, &n)) {
                Ok(hs) => break hs,
                _ => x += 1u32,
            }
        };
        let order = order_of(&hs, &nn, &p_half, &q_half);
        let lambda = Integer::from(2u32) * &p_half * &q_half;
        if order == lambda {
            full += 1;
        }
    }
    assert_eq!(full, KEYS, "полную λ дали {full} ключей из {KEYS}");
}

/// Один ключ боевой длины — чтобы «довод не зависит от длины» не
/// осталось словами.
#[test]
fn один_ключ_боевой_длины() {
    let p = safe_prime(1024);
    let q = safe_prime(1024);
    let p_half = Integer::from(&p - 1u32) / 2u32;
    let q_half = Integer::from(&q - 1u32) / 2u32;
    let n = Integer::from(&p * &q);
    let nn = Integer::from(&n * &n);

    let mut x = Integer::from(3u32);
    let hs = loop {
        match derive_h(&x, &n).and_then(|h| derive_hs(&h, &n)) {
            Ok(hs) => break hs,
            _ => x += 1u32,
        }
    };

    assert_eq!(
        order_of(&hs, &nn, &p_half, &q_half),
        Integer::from(2u32) * &p_half * &q_half
    );
}
