//! Почему безопасные простые — ГЛАВНАЯ проверка НАШЕГО ключа.
//!
//! Здесь не утверждается, что `validate_private` возвращает нужный
//! вариант ошибки. Здесь показывается, ЧТО происходит с ключом, который
//! эта проверка отвергает: модуль раскладывается, и открытый текст
//! снимается целиком — при том что ключ блюмов, `gcd(p−1, q−1) = 2`, а
//! простые далеки друг от друга.
//!
//! Первая редакция файла доказывала не своё утверждение, и это стоит
//! записать. Она снимала показатель `r` методом Полига–Хеллмана, называя
//! это атакой на короткий показатель, — но за черту «дальше только `n` и
//! шифротекст» проносила две величины, которых у наблюдателя нет: сам
//! `hs` (он выводится шифрующим из случайного `x` и наружу не отдаётся)
//! и порядок `hs` (он вычислялся из `λ`, то есть из `p` и `q`).
//!
//! Хуже, что такой ключ ломается вообще без всякой связи с коротким
//! показателем: при гладком `p−1` работает Поллард `p−1`, и это метод
//! против МОДУЛЯ, а не против рандомизатора. То есть контрпример
//! показывал «гладкое `p−1` губит любой Paillier» — верное и важное
//! утверждение, но другое.
//!
//! Поэтому здесь ровно оно и доказывается, честно: в атаке участвует
//! ТОЛЬКО `n`. А требование неглаткости порядка `hs`, специфичное для
//! короткого показателя, стережёт `DegenerateHs` — см.
//! `tests/degenerate_x.rs`.
//!
//! Чего здесь БОЛЬШЕ НЕТ: тестов на пробы чужого модуля. Проб не
//! осталось — `validate_public` проверяет длину, и только, как и
//! положено *partial public key validation*. Разбор, почему проб быть не
//! должно, — в её докстринге.

use paillier::keys::{
    derive_h, derive_hs, validate_private, validate_public, KeyError,
    MIN_MODULUS_BITS,
};
use rand::seq::SliceRandom;
use rand::Rng;
use rug::integer::{IsPrime, Order};
use rug::ops::RemRounding;
use rug::Integer;

/// Простые для сборки гладкого `p−1`. Разные наборы у `p` и `q`, чтобы
/// `gcd(p−1, q−1) = 2` — иначе отказ пришёл бы по другой ветке и тест
/// доказывал бы не то.
fn small_primes(from: u32, to: u32) -> Vec<u32> {
    (from..to)
        .filter(|c| Integer::from(*c).is_probably_prime(30) != IsPrime::No)
        .collect()
}

/// Блюмово простое `p = 2·s + 1`, где `s` — произведение различных
/// малых простых из `pool`. Все делители `p−1` меньше верхней границы
/// набора, поэтому `p−1` гладкое.
fn smooth_blum_prime(pool: &[u32], target_bits: u32) -> (Integer, Vec<u32>) {
    let mut rng = rand::thread_rng();
    loop {
        let mut chosen: Vec<u32> = Vec::new();
        let mut s = Integer::from(1);
        let mut shuffled = pool.to_vec();
        shuffled.shuffle(&mut rng);
        for prime in shuffled {
            if s.significant_bits() >= target_bits {
                break;
            }
            chosen.push(prime);
            s *= prime;
        }
        let candidate = Integer::from(&s * 2u32) + 1u32;
        if candidate.is_probably_prime(40) != IsPrime::No {
            // `s` — произведение нечётных простых, значит нечётно,
            // значит `p = 2s+1 ≡ 3 (mod 4)`. Блюмовость выполнена.
            assert_eq!(candidate.clone() % 4u32, 3);
            chosen.sort_unstable();
            return (candidate, chosen);
        }
    }
}

/// Поллард `p−1`: `a^M mod n` при `M = lcm(1..bound)`.
///
/// Единственный вход — `n`. Ни `p`, ни `q`, ни `λ`, ни `hs`.
fn pollard_p_minus_1(n: &Integer, bound: u32) -> Option<Integer> {
    let mut base = Integer::from(2);
    for k in 2..=bound {
        base = base.pow_mod(&Integer::from(k), n).ok()?;
        if k % 512 == 0 {
            let divisor = Integer::from(&base - 1u32).gcd(n);
            if divisor > 1 && divisor < *n {
                return Some(divisor);
            }
        }
    }
    let divisor = Integer::from(&base - 1u32).gcd(n);
    if divisor > 1 && divisor < *n {
        Some(divisor)
    } else {
        None
    }
}

#[test]
fn нижняя_граница_длины_есть_и_у_владельца() {
    // `validate_private` публична и заявлена как проверка ключа, а её
    // граница длины держалась только тем, что `generate_keypair`
    // проверяет раньше. 23 и 59 — настоящие безопасные простые
    // (11 и 29 просты), блюмовы, `gcd(22, 58) = 2`: всё остальное здесь
    // в порядке, отвергает ровно длина.
    let p = Integer::from(23);
    let q = Integer::from(59);

    assert_eq!(validate_private(&p, &q), Err(KeyError::ModulusTooShort));
}

#[test]
fn короткий_модуль_отвергается_при_импорте() {
    let n = (Integer::from(1) << 2000u32) + 1u32;

    assert_eq!(validate_public(&n), Err(KeyError::ModulusTooShort));
}

#[test]
fn слишком_длинный_модуль_отвергается() {
    let n = (Integer::from(1) << 9000u32) + 1u32;

    assert_eq!(validate_public(&n), Err(KeyError::ModulusTooLong));
}

#[test]
fn модуль_штатной_длины_принимается() {
    // Обратная сторона границ: без этого «починить» их можно было бы
    // полным запретом, и оба теста выше остались бы зелёными.
    let n = (Integer::from(1) << 3071u32) + 1u32;

    assert_eq!(validate_public(&n), Ok(()));
}

#[test]
fn ключ_с_гладкой_лямбдой_отдаёт_открытый_текст_и_потому_отвергается() {
    // Наборы не пересекаются — тогда gcd(p−1, q−1) = 2 и отказ придёт
    // именно по безопасности простых, а не по gcd.
    let (p, factors_p) = smooth_blum_prime(&small_primes(3, 30_000), 1030);
    let (q, factors_q) = smooth_blum_prime(&small_primes(30_000, 65_000), 1050);
    assert!(
        factors_p.iter().all(|f| !factors_q.contains(f)),
        "наборы делителей обязаны не пересекаться",
    );

    let n = Integer::from(&p * &q);
    let nn = Integer::from(&n * &n);
    println!(
        "|p| = {}, |q| = {}, |n| = {}",
        p.significant_bits(),
        q.significant_bits(),
        n.significant_bits(),
    );

    // 1. Ключ длиннее нижней границы, блюмов, gcd верный, простые
    //    далеки — и всё же отвергается, потому что не безопасные.
    assert!(
        n.significant_bits() >= MIN_MODULUS_BITS,
        "длина не должна быть причиной",
    );
    assert_eq!(p.clone() % 4u32, 3);
    assert_eq!(q.clone() % 4u32, 3);
    assert_eq!(Integer::from(&p - 1u32).gcd(&Integer::from(&q - 1u32)), 2);
    let difference = Integer::from(&p - &q).abs();
    assert!(
        difference.significant_bits() + 100
            >= p.significant_bits().max(q.significant_bits()),
        "простые не должны быть близки — иначе отказ пришёл бы по Ферма",
    );
    assert_eq!(
        validate_private(&p, &q),
        Err(KeyError::NotSafePrimes),
        "ключ с гладкой λ обязан отвергаться",
    );

    // 2. Теперь — что было бы, если бы не отвергался. Шифротекст
    //    строится НАШИМ кодом.
    let x = Integer::from(&n / 3u32) + 12345u32;
    let h = derive_h(&x, &n).expect("h");
    let hs = derive_hs(&h, &n).expect("hs");
    let exponent_bits = n.significant_bits() / 2;
    let mut raw = vec![0u8; ((exponent_bits + 7) / 8) as usize];
    rand::thread_rng().fill(&mut raw[..]);
    let r = Integer::from_digits(&raw, Order::MsfBe);
    let secret = Integer::from(4_242_424_242u64);
    let cipher = (Integer::from(1 + secret.clone() * &n)
        * hs.clone().pow_mod(&r, &nn).unwrap())
        % nn.clone();

    // --- дальше в ход идёт ТОЛЬКО `n` и шифротекст ---
    let started = std::time::Instant::now();
    let factor = pollard_p_minus_1(&n, 70_000).expect("Поллард обязан справиться");
    let other = Integer::from(&n / &factor);
    println!(
        "Поллард p−1 разложил n за {:?}: делитель {} бит",
        started.elapsed(),
        factor.significant_bits(),
    );
    assert_eq!(Integer::from(&factor * &other), n, "делитель настоящий");

    // Имея `p` и `q`, наблюдатель расшифровывает как владелец ключа.
    let lambda = Integer::from(&factor - 1u32).lcm(&Integer::from(&other - 1u32));
    let numerator = cipher.clone().pow_mod(&lambda, &nn).unwrap();
    let l_value = Integer::from(&numerator - 1u32) / &n;
    let mu = Integer::from(&lambda % &n).invert(&n).expect("gcd(λ, n) = 1");
    let plain = (l_value * mu).rem_euc(n.clone());
    println!("открытый текст снят за {:?}", started.elapsed());

    assert_eq!(
        plain, secret,
        "открытый текст обязан сниматься — в этом и смысл отказа выше",
    );
}
