//! Наша расшифровка обязана давать РОВНО то же, что крейт.
//!
//! Мы переписали её ради `secure_pow_mod` вместо `pow_mod` — то есть
//! ради постоянства времени по секретному показателю, а НЕ ради другого
//! результата. Значит и проверять надо совпадение результатов, а не
//! круг: круг зелен и на неверной расшифровке, если шифрование ошибается
//! так же.
//!
//! Эталон — `fast_paillier::DecryptionKey::decrypt`, независимая
//! реализация того же алгоритма на тех же простых.

use fast_paillier::{DecryptionKey, Plaintext};
use paillier::secret::Decryptor;
use rug::Integer;

/// Ключ поменьше боевого: алгебра от размера не зависит, а прогон
/// должен быть быстрым. Простые ДАЛЕКО друг от друга — чтобы фикстуру
/// нельзя было скопировать как образец.
fn key() -> (DecryptionKey, Integer, Integer) {
    let mut p = (Integer::from(1) << 256u32) + 1u32;
    p.next_prime_mut();
    let mut q = (Integer::from(1) << 200u32) + 7u32;
    q.next_prime_mut();
    let dk = DecryptionKey::from_primes(
        Plaintext::from_rug(p.clone()),
        Plaintext::from_rug(q.clone()),
    )
    .expect("ключ собирается");
    (dk, p, q)
}

fn to_rug(value: &Plaintext) -> Integer {
    value.to_string().parse().expect("десятичная запись")
}

#[test]
fn our_decryption_matches_the_reference_crate() {
    let (dk, p, q) = key();
    let ours = Decryptor::new(&p, &q).expect("расшифровщик собирается");
    let ek = dk.encryption_key();
    let n = to_rug(ek.n());

    // Значения по всему диапазону, включая знак и края.
    let mut probes = vec![
        Integer::from(0),
        Integer::from(1),
        Integer::from(-1),
        Integer::from(1234567890u64),
        Integer::from(-987654321i64),
    ];
    probes.push(Integer::from(&n / 2u32) - 1u32);
    probes.push(-(Integer::from(&n / 2u32) - 1u32));

    let mut rng = rand::thread_rng();
    for value in probes {
        let plain = Plaintext::from_rug(value.clone());
        let (cipher, _nonce) =
            ek.encrypt_with_random(&mut rng, &plain).expect("шифрование");
        let expected = to_rug(&dk.decrypt(&cipher).expect("крейт расшифровывает"));

        let raw = cipher.to_bytes_msf();
        let got = ours
            .decrypt(&Integer::from_digits(&raw, rug::integer::Order::MsfBe))
            .expect("наш расшифровщик");

        assert_eq!(got, expected, "значение {value}");
        assert_eq!(got, value, "и это исходное число");
    }
}

#[test]
fn an_invalid_ciphertext_is_refused() {
    let (dk, p, q) = key();
    let ours = Decryptor::new(&p, &q).expect("расшифровщик");
    let n = to_rug(dk.encryption_key().n());
    let nn = Integer::from(&n * &n);

    // Ноль: необратим, шифротекстом не является ни при каком тексте.
    assert_eq!(ours.decrypt(&Integer::from(0)), None);
    // Ровно модуль: вне `[1, n²)`.
    assert_eq!(ours.decrypt(&nn), None);
    // Больше модуля.
    assert_eq!(ours.decrypt(&(nn.clone() + 1u32)), None);
    // Необратимый: `n` делит `n²`, значит `gcd(n, n) = n ≠ 1`.
    assert_eq!(ours.decrypt(&n), None);
}

#[test]
fn a_homomorphic_sum_decrypts_with_ours() {
    // Отдельно от круга: сумма — это произведение шифротекстов, то есть
    // вход, которого шифрование напрямую не порождает.
    let (dk, p, q) = key();
    let ours = Decryptor::new(&p, &q).expect("расшифровщик");
    let ek = dk.encryption_key();
    let n = to_rug(ek.n());
    let nn = Integer::from(&n * &n);

    let mut rng = rand::thread_rng();
    let mut product = Integer::from(1);
    let mut total = Integer::from(0);
    for value in [10i64, -3, 500, -7] {
        let plain = Plaintext::from_rug(Integer::from(value));
        let (cipher, _nonce) =
            ek.encrypt_with_random(&mut rng, &plain).expect("шифрование");
        let raw = cipher.to_bytes_msf();
        product = product * Integer::from_digits(&raw, rug::integer::Order::MsfBe) % &nn;
        total += value;
    }

    assert_eq!(ours.decrypt(&product), Some(total));
}
