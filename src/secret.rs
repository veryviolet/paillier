//! Расшифровка: китайская теорема плюс возведение, безопасное к
//! показателю.
//!
//! # Зачем своя, если у крейта есть
//!
//! `fast-paillier` расшифровывает через `rug::Integer::pow_mod`, то есть
//! через `mpz_powm` из GMP. Показатель там выведен из `λ` — из
//! ДОЛГОВРЕМЕННОГО секрета ключа.
//!
//! А документация самого GMP говорит про `mpz_powm` прямо: для
//! секретных показателей нужен `mpz_powm_sec`. Разница в том, что
//! `mpz_powm` — оконное возведение с обращениями к таблице по битам
//! показателя, а `mpz_powm_sec` читает всю таблицу на каждом шаге.
//!
//! Масштаб разницы стоит назвать. Всё, что чинилось в шифровании, —
//! канал вокруг разового `r`, ценой в доли бита за сообщение. Здесь под
//! каналом сам `λ`: он один на весь срок ключа, и утечка накапливается
//! по всем расшифровкам, а не начинается заново каждый раз.
//!
//! # Что делает эта функция
//!
//! То же, что `heu` (`decryptor.cc:32-52`), и то же, что крейт, но с
//! безопасным возведением:
//!
//! 1. проверка шифротекста: `c` обязан лежать в `Z*_{n²}`;
//! 2. `c^(p−1) mod p²` и `c^(q−1) mod q²` — ДВА возведения с короткими
//!    показателями вместо одного длинного по `n²`;
//! 3. `L`-функция в каждой компоненте, умножение на заготовленный
//!    обратный;
//! 4. сборка китайской теоремой;
//! 5. знаковый представитель: `m > n/2` означает отрицательное.
//!
//! Китайская теорема здесь не украшение: без неё показатель вдвое
//! длиннее и модуль вдвое шире, то есть вчетверо дороже.

use rug::ops::RemRounding;
use rug::Integer;

/// Заготовленное для расшифровки. Считается ОДИН РАЗ при сборке ключа.
///
/// Всё, что здесь лежит, выводится из `p` и `q` и является секретом.
pub struct Decryptor {
    n: Integer,
    /// `n²` — заготовлено, а не пересчитывается на каждом вызове.
    n_square: Integer,
    n_half: Integer,
    p: Integer,
    q: Integer,
    p_square: Integer,
    q_square: Integer,
    /// `p − 1` и `q − 1` — показатели компонент.
    p_minus_1: Integer,
    q_minus_1: Integer,
    /// `(L_p(g^(p−1) mod p²))^{-1} mod p`, и то же для `q`.
    hp: Integer,
    hq: Integer,
    /// `p^{-1} mod q` — для сборки.
    p_inverse_mod_q: Integer,
}

/// `L(x) = (x − 1) / divisor`, точное деление.
///
/// Точное, а не с остатком: `x ≡ 1 (mod divisor)` по построению, и если
/// это вдруг не так, значит вход не шифротекст. Остаток здесь был бы
/// молча отброшен.
fn l_function(value: &Integer, divisor: &Integer) -> Option<Integer> {
    let shifted = Integer::from(value - 1u32);
    let (quotient, remainder) = shifted.div_rem(divisor.clone());
    if remainder == 0 {
        Some(quotient)
    } else {
        None
    }
}

impl Decryptor {
    pub fn new(p: &Integer, q: &Integer) -> Option<Self> {
        let n = Integer::from(p * q);
        let n_square = Integer::from(&n * &n);
        let p_square = Integer::from(p * p);
        let q_square = Integer::from(q * q);
        let p_minus_1 = Integer::from(p - 1u32);
        let q_minus_1 = Integer::from(q - 1u32);

        // `g = n + 1`, поэтому `g^(p−1) mod p² = 1 + (p−1)·n mod p²`.
        // Считается прямо, без возведения.
        let gp = (Integer::from(&p_minus_1 * &n) + 1u32) % &p_square;
        let gq = (Integer::from(&q_minus_1 * &n) + 1u32) % &q_square;
        let hp = l_function(&gp, p)?.invert(p).ok()?;
        let hq = l_function(&gq, q)?.invert(q).ok()?;

        let p_inverse_mod_q = p.clone().invert(q).ok()?;
        let n_half = Integer::from(&n >> 1u32);

        Some(Self {
            n,
            n_square,
            n_half,
            p: p.clone(),
            q: q.clone(),
            p_square,
            q_square,
            p_minus_1,
            q_minus_1,
            hp,
            hq,
            p_inverse_mod_q,
        })
    }

    /// Открытый текст как ЗНАКОВОЕ целое, или `None` на негодном входе.
    ///
    /// `secure_pow_mod` вместо `pow_mod` — единственное отличие от
    /// реализации dfns по существу, и ради него всё и переписано.
    ///
    /// # Сторожа у этой строки НЕТ, и это признано, а не забыто
    ///
    /// Проверить подмену нечем. Результат у обеих функций одинаков.
    /// Разброс времени по вызовам тоже: показатель у ключа фиксирован,
    /// значит обе детерминированы, а утечка идёт через кэш, не через
    /// стенные часы.
    ///
    /// Остаётся отличие в скорости, и я пробовал сторожить им. Замерено:
    /// здоровый код даёт отношение к небезопасному пути 1.68,
    /// подменённый — 1.40, при разбросе машины около 15 %. Порог между
    /// ними имел бы запас в 12 % — это флапающий тест, а флапающий тест
    /// хуже отсутствующего: он приучает не верить красноте. Тест был
    /// написан и удалён.
    ///
    /// Сама цена свойства меряется отдельно и без подмен —
    /// `benches/secure_pow.rs`: на длинах компонент китайской теоремы
    /// `powm_sec` дороже `powm` в 1.54 раза при `|n| = 2048` и в 1.67
    /// при 3072.
    ///
    /// Значит здесь работает только чтение кода. Строка одна, и она
    /// перед вами.
    pub fn decrypt(&self, cipher: &Integer) -> Option<Integer> {
        if *cipher < 1 || *cipher >= self.n_square {
            return None;
        }
        // Шифротекст обязан быть обратим: иначе он не образ шифрования
        // ни при каком открытом тексте. Крейт проверяет это же
        // (`in_mult_group_of`), и проверка здесь не лишняя — `add_many`
        // её не делает, потому что там она стоила бы дороже операции.
        if Integer::from(cipher.gcd_ref(&self.n)) != 1 {
            return None;
        }

        let mp = cipher
            .clone()
            .secure_pow_mod(&self.p_minus_1, &self.p_square);
        let mp = l_function(&mp, &self.p)? * &self.hp % &self.p;

        let mq = cipher
            .clone()
            .secure_pow_mod(&self.q_minus_1, &self.q_square);
        let mq = l_function(&mq, &self.q)? * &self.hq % &self.q;

        // Сборка: `m = mp + p · ((mq − mp) · p^{-1} mod q)`.
        let difference = (Integer::from(&mq - &mp) * &self.p_inverse_mod_q)
            .rem_euc(self.q.clone());
        let plain = mp + Integer::from(&self.p * &difference);

        // Знаковый представитель. Кодирование использует весь диапазон
        // `(−n/2, n/2)`, и без этого шага отрицательные вернулись бы
        // как огромные положительные.
        if plain > self.n_half {
            Some(plain - &self.n)
        } else {
            Some(plain)
        }
    }
}
