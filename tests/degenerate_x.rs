//! `x = 1` обязан отвергаться.
//!
//! Он проходит и `gcd(x, n) = 1`, и проверку символом Якоби — при
//! блюмовых простых `jacobi(−1, p) = jacobi(−1, q) = −1`. Даёт `h = −1`
//! и `hs = n²−1`, а `hs^r` принимает ровно два значения. Круг и
//! гомоморфность при этом верны, и наблюдатель, знающий только `n`,
//! читает открытый текст из любого шифротекста.

use paillier::keys::{derive_h, derive_h_checked, derive_hs, KeyError};
use rug::Integer;

/// Маленький, но **действительный** модуль Paillier.
///
/// `p = 2·11+1 = 23`, `q = 2·29+1 = 59` — оба безопасные простые, оба
/// `≡ 3 (mod 4)`, `gcd(p−1, q−1) = 2`, и, что здесь решающее,
/// `gcd(λ, n) = 1`, то есть `µ = λ⁻¹ mod n` существует и расшифровка
/// определена.
///
/// Прежде тут стояло `q = 47`. На нём `q − 1 = 2·23`, то есть `p`
/// делит `λ`, `gcd(λ, n) = 23`, и `µ` не существует вовсе:
/// `DecryptionKey::from_primes` такой ключ отверг бы. Схема на нём не
/// работает, и отображение `h ↦ h^n mod n²` перестаёт быть
/// инъективным — вырожденных `x` там оказывается 90 из тысячи вместо
/// двух. То есть фикстура искажала ровно то поведение, которое этот
/// файл проверяет.
fn small_key() -> (Integer, Integer, Integer) {
    let p = Integer::from(23);
    let q = Integer::from(59);
    let n = Integer::from(&p * &q);
    (p, q, n)
}

#[test]
fn one_is_refused_before_hs_is_derived() {
    let (_, _, n) = small_key();

    assert_eq!(derive_h(&Integer::from(1), &n), Err(KeyError::BadX));
}

#[test]
fn zero_and_the_upper_bound_are_refused_by_range() {
    let (_, _, n) = small_key();

    assert_eq!(derive_h(&Integer::from(0), &n), Err(KeyError::BadX));
    // `x = n−1` даёт то же `h = −1`, что и единица.
    let top = Integer::from(&n - 1u32);
    assert_eq!(derive_h(&top, &n), Err(KeyError::BadX));
}

#[test]
fn the_sign_check_is_green_on_one_and_therefore_not_a_defence() {
    // Ради этого тест и написан: показать, что символ Якоби здесь
    // ничего не ловит, и что защищает только сужение диапазона.
    let (p, q, n) = small_key();
    let h_minus_one = Integer::from(&n - 1u32);

    assert_eq!(h_minus_one.jacobi(&p), -1);
    assert_eq!(h_minus_one.jacobi(&q), -1);
}

#[test]
fn second_line_of_defence_fires_on_real_input() {
    // Нетривиальные корни из единицы: `x² ≡ 1 (mod n)` при `x ∉ {1, n−1}`.
    // Такое `x` проходит диапазон, `gcd` и Якоби — и вырождается только
    // на `hs`. То есть второй рубеж не «на всякий случай»: он ловит
    // вход, который все предыдущие проверки принимают.
    let (p, q, n) = small_key();
    let limit = n.to_u32().unwrap();

    let mut found = 0;
    for candidate in 2..(limit - 1) {
        let x = Integer::from(candidate);
        if Integer::from(&x * &x) % &n != 1 {
            continue;
        }
        found += 1;
        // Все предыдущие проверки пройдены…
        let h = derive_h_checked(&x, &p, &q, &n)
            .expect("нетривиальный корень обязан пройти диапазон и Якоби");
        // …и вырождение ловит только вывод `hs`.
        assert_eq!(derive_hs(&h, &n), Err(KeyError::DegenerateHs));
    }
    assert!(found > 0, "нетривиальных корней не нашлось — набор не тот");
}

#[test]
fn degenerate_hs_is_refused_even_when_planted_by_hand() {
    let (_, _, n) = small_key();

    // `h = −1` — то, что дало бы `x = 1`, если бы диапазон не сужали.
    assert_eq!(
        derive_hs(&Integer::from(&n - 1u32), &n),
        Err(KeyError::DegenerateHs),
    );
    // И `h = 1`: `hs = 1` даёт `c = 1 + m·n` ровно, то есть снимает
    // рандомизацию целиком.
    assert_eq!(derive_hs(&Integer::from(1), &n), Err(KeyError::DegenerateHs));
}

#[test]
fn a_usable_x_passes_or_the_refusals_above_mean_nothing() {
    let (p, q, n) = small_key();
    let limit = n.to_u32().unwrap();

    let mut accepted = 0;
    for candidate in 2..(limit - 1) {
        let x = Integer::from(candidate);
        if let Ok(h) = derive_h_checked(&x, &p, &q, &n) {
            if derive_hs(&h, &n).is_ok() {
                accepted += 1;
            }
        }
    }
    assert!(accepted > 0, "не принято ни одного x — отказы бессмысленны");
}
