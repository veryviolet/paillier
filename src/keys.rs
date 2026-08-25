//! Ключи: порождение, проверка и вывод `hs`.
//!
//! Здесь живёт всё, от чего зависит стойкость короткого показателя.
//! Разбор — в `docs/short-exponent-security.md`.
//!
//! Устройство в одну строку: `hs` **не импортируется**, а выводится
//! шифрующим из одного `n`. Проверить импортированный `hs` вычислением
//! невозможно — проба на гладкость при границе `B` удостоверяет лишь
//! `√B` работы, а стоит `π(B)·|n|` возведений в квадрат; чтобы
//! удостоверить 128 бит, нужна граница `2^256`. Вывод на месте
//! закрывает этот класс целиком и не требует ни одной проверки чужого
//! материала.

use rug::integer::IsPrime;
use rug::Integer;

/// Минимальный запас по разности простых, в битах. Меньшая разность
/// открывает разложение методом Ферма. В `fast-paillier` такой проверки
/// нет вовсе — она наша.
const PQ_DIFFERENCE_SLACK: u32 = 2;

/// Раундов Миллера–Рабина при проверке `(p−1)/2` на простоту.
const PRIMALITY_ROUNDS: u32 = 40;

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// `(p−1)/2` или `(q−1)/2` не просто — простые не безопасные.
    ///
    /// ГЛАВНАЯ проверка ключа. Именно безопасные простые дают
    /// `λ = 2p′q′`, то есть большой простой делитель порядка.
    /// Блюмовость этого не даёт: существует ключ, где она выполнена,
    /// порядок 597 бит, а открытый текст снимается за семь секунд,
    /// потому что `λ` гладкая.
    NotSafePrimes,
    /// `p ≢ 3 (mod 4)` или `q ≢ 3 (mod 4)`. Вспомогательная: даёт
    /// `⟨h⟩ ⊆ J_n`, то есть свойство про расположение, не про величину.
    NotBlum,
    /// `gcd(p−1, q−1) ≠ 2`. Вспомогательная.
    BadGcd,
    /// Простые слишком близки — разложение методом Ферма.
    PrimesTooClose,
    /// Знак `h` потерян: получился квадратичный вычет.
    HNotAntiResidue,
    /// `x` вне `[2, n−2]` либо не взаимно просто с `n`.
    BadX,
    /// `hs` вырожден: его порядок не больше двух.
    ///
    /// Единственный отказ, который ловит `x = 1`. Тот проходит и
    /// `gcd(x, n) = 1`, и проверку символом Якоби — при блюмовых
    /// простых `jacobi(−1, p) = jacobi(−1, q) = −1`, — но даёт
    /// `h = −1` и `hs = n²−1`, а `hs^r` принимает ровно ДВА значения.
    /// Круг и гомоморфность при этом верны, и наблюдатель, знающий
    /// только `n`, читает открытый текст из любого шифротекста.
    ///
    /// Это не атака, а отказ генератора случайных: обнулённый буфер
    /// даёт `x = 0` и ловится по `gcd`, неинициализированный даёт
    /// `x = 1` и не ловится больше ничем.
    DegenerateHs,
    /// Возведение в степень не определено.
    PowModUndefined,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            KeyError::NotSafePrimes =>
                "primes are not safe: (p−1)/2 or (q−1)/2 is composite. Safe \
                 primes are what gives the order of h a large prime factor; \
                 without them the order can be smooth and the short exponent \
                 falls to Pohlig–Hellman while every correctness check stays \
                 green",
            KeyError::NotBlum =>
                "primes are not Blum (need p ≡ q ≡ 3 mod 4): h = −x² would \
                 not sit outside the group of squares",
            KeyError::BadGcd =>
                "gcd(p−1, q−1) ≠ 2: Z*_n gains an extra cyclic component",
            KeyError::PrimesTooClose =>
                "p and q are too close: the modulus falls to Fermat \
                 factorisation",
            KeyError::HNotAntiResidue =>
                "h is a quadratic residue: the sign was lost. Nothing about \
                 correctness changes, which is exactly why this is checked \
                 here",
            KeyError::BadX =>
                "x must lie in [2, n−2] and be coprime with n",
            KeyError::DegenerateHs =>
                "hs is degenerate: its order is at most two, so the \
                 randomiser takes at most two values and the plaintext is \
                 readable by anyone holding n. Correctness is unaffected — \
                 which is why this is checked and not assumed",
            KeyError::PowModUndefined =>
                "modular exponentiation is undefined for these arguments",
        };
        write!(f, "{text}")
    }
}

impl std::error::Error for KeyError {}

/// Проверки НАШЕГО ключа при порождении. Требуют `p` и `q`, поэтому
/// возможны только у владельца.
///
/// `fast-paillier` из этого не проверяет ничего: безопасные простые он
/// строит, но нигде не утверждает, а `from_primes` и десериализация
/// обходят и это — причём докстринг самого крейта у `from_primes`
/// гласит, что простые ОБЯЗАНЫ быть безопасными.
///
/// Чего здесь НЕТ сознательно: проверки `gcd(λ, n) = 1`. Каждая
/// проверка в этом файле сторожит **беззвучный** отказ — тот, при
/// котором круг и гомоморфность зелены, а приватности нет: `x = 1`,
/// `hs = 1`, гладкий порядок. Их не поймает никто, кроме нас.
/// `gcd(λ, n) ≠ 1` — противоположный случай: `µ` не существует,
/// расшифровка не определена, и `from_primes` возвращает ошибку. Это
/// самый громкий отказ из возможных, и он уже пойман ниже по течению —
/// единственным условием, в котором крейт строже нас.
///
/// Важное для тестов: на ключе, порождённом безопасными простыми, три
/// вспомогательные ветки **недостижимы**. `p = 2p′+1` с нечётным
/// простым `p′` даёт `p ≡ 3 (mod 4)` тождественно, а `gcd(2p′, 2q′) = 2`
/// при `p′ ≠ q′`. Проверять их надо собранными руками `p` и `q`, иначе
/// тест зелен всегда и не запускает ни одной из них.
pub fn validate_private(p: &Integer, q: &Integer) -> Result<(), KeyError> {
    for prime in [p, q] {
        let half = Integer::from(prime - 1u32) / 2u32;
        if half.is_probably_prime(PRIMALITY_ROUNDS) == IsPrime::No {
            return Err(KeyError::NotSafePrimes);
        }
    }
    if p.clone() % 4u32 != 3 || q.clone() % 4u32 != 3 {
        return Err(KeyError::NotBlum);
    }
    if Integer::from(p - 1u32).gcd(&Integer::from(q - 1u32)) != 2 {
        return Err(KeyError::BadGcd);
    }
    let prime_bits = p.significant_bits().max(q.significant_bits());
    let difference = Integer::from(p - q).abs();
    if difference.significant_bits() + PQ_DIFFERENCE_SLACK < prime_bits {
        return Err(KeyError::PrimesTooClose);
    }
    Ok(())
}

/// `h = −x² mod n`.
///
/// Диапазон `x` сужен до `[2, n−2]`: единица даёт `h = −1`, а
/// вырождение отсюда не ловится ни `gcd`, ни символом Якоби.
pub fn derive_h(x: &Integer, n: &Integer) -> Result<Integer, KeyError> {
    if *x < 2 || *x > Integer::from(n - 2u32) {
        return Err(KeyError::BadX);
    }
    if Integer::from(x.gcd_ref(n)) != 1 {
        return Err(KeyError::BadX);
    }
    let square = Integer::from(x * x) % n;
    Ok(Integer::from(n - square) % n)
}

/// `h = −x² mod n` со знаком, проверенным символом Якоби.
///
/// Знак проверяется там, где есть `p` и `q`, — то есть у владельца
/// ключа. Шифрующий, выводящий `hs` из одного `n`, этого сделать не
/// может.
///
/// Почему пропуск проверки у шифрующего допустим: при честном `n`
/// (безопасные простые) `p ≡ q ≡ 3 (mod 4)` выполняется само собой, и
/// знак верен по построению. При нечестном `n` знак — наименьшая из бед.
///
/// Прежде здесь стоял другой довод — «расшифровка при любом `x` верна».
/// Он неверен как обоснование: верность расшифровки ничего не говорит о
/// качестве рандомизатора, и именно такая подмена «корректно» на
/// «стойко» оправдала бы и пропуск проверки на `x = 1`.
pub fn derive_h_checked(
    x: &Integer,
    p: &Integer,
    q: &Integer,
    n: &Integer,
) -> Result<Integer, KeyError> {
    let h = derive_h(x, n)?;
    if h.jacobi(p) != -1 || h.jacobi(q) != -1 {
        return Err(KeyError::HNotAntiResidue);
    }
    Ok(h)
}

/// `hs = h^n mod n²`, с отказом на вырождении.
///
/// Считается ОДИН РАЗ на модуль и кэшируется: 0.30 с при `|n| = 3072`.
/// На каждое сообщение это съело бы весь выигрыш от короткого
/// показателя.
///
/// Ошибку **не подменяем значением**. Прежде здесь стояло
/// `unwrap_or_else(|_| 1)`, а `hs = 1` даёт `c = 1 + m·n` ровно, то есть
/// снимает приватность целиком. Нейтрального значения по умолчанию у
/// элемента группы не бывает, а единица — наихудшее из возможных.
pub fn derive_hs(h: &Integer, n: &Integer) -> Result<Integer, KeyError> {
    let nn = Integer::from(n * n);
    let hs = h
        .clone()
        .pow_mod(n, &nn)
        .map_err(|_| KeyError::PowModUndefined)?;
    // `ord(hs) ≤ 2` — единственное вырождение, которое может дать
    // одиночное `x`, и единственное, которое не ловят проверки выше.
    if hs <= 1 || hs == Integer::from(&nn - 1u32) {
        return Err(KeyError::DegenerateHs);
    }
    Ok(hs)
}
