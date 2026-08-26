//! Привязка Paillier к Python: fast-paillier + pyo3.
//!
//! Криптографию не пишем — она в крейте. Здесь склейка: кодирование
//! float в целое, сериализация в байты и параллельное шифрование.
//!
//! Записи МИНИМАЛЬНЫЕ, а не фиксированной ширины: замерено `[255, 256]`
//! байт на тысяче шифрований одним ключом. Нарезать буфер постоянным
//! шагом нельзя.
//!
//! Бэкенд `rug` выбран не по вкусу: бэкенд `num-bigint`, включённый в
//! крейте по умолчанию, тянет `glass_pumpkin`, а тот — `core2`, у
//! которого **все** версии отозваны автором. С `backend-rug` этой
//! цепочки нет вовсе, и он же считает на GMP.
//!
//! Шифрование идёт КОРОТКИМ ПОКАЗАТЕЛЕМ: вместо `r^n` со случайным
//! основанием — `hs^r` с фиксированным. Приём взят из `heu`, разобран
//! в `docs/heu-comparison.md`; что при этом добавляется к
//! предположениям о стойкости — в `docs/short-exponent-security.md`.

// Единственная дверь, через которую свидетельство `keys::Validated`
// всё же подделывается, — `unsafe`: `mem::zeroed` собирает тип нулевого
// размера из ничего. Закрываем её здесь, а не надеемся, что никто не
// напишет. `unsafe` в этом крейте не нужен нигде.
#![forbid(unsafe_code)]

pub mod keys;

use fast_paillier::{Ciphertext, DecryptionKey, EncryptionKey, Plaintext};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::Rng;
use rayon::prelude::*;
use rug::integer::Order;
use rug::ops::RemRounding;
use rug::Integer;

/// Масштаб кодирования float в целое.
///
/// Отсюда же и цена дробности: всё, что по модулю меньше `1/(2·SCALE)`,
/// округляется в ноль. Это свойство неподвижной точки, а не потеря:
/// `4e-9` кодируется нулём и расшифровывается нулём.
const SCALE: f64 = 1e8;

/// Сколько слагаемых обязана выдержать сумма без переполнения.
///
/// Поштучной проверки диапазона МАЛО. Три законных значения по
/// `2.29e299` каждое проходят её на 1024-битном ключе, а их сумма
/// выходит за `n/2` и расшифровывается как `−4.57e299` — конечное,
/// правдоподобное число не того знака. Ровно тот отказ, который описан
/// в тексте ошибки о диапазоне, только этажом выше.
///
/// Проверить сумму на месте нельзя: слагаемые зашифрованы. Поэтому
/// запас резервируется ЗАРАНЕЕ — принимается только такое `x`, что
/// `|x| ≤ n/(2·SUM_HEADROOM_TERMS)`, и `add_many` берёт не более
/// `SUM_HEADROOM_TERMS` слагаемых.
///
/// Чем эта пара НЕ является: гарантией по построению. Прежде здесь так
/// и было написано, и это неверно — счётчик повызовный, а результат
/// `add_many` можно подать во второй вызов. Два законных вызова дают
/// `2^40` слагаемых, и никакая проверка этого не видит: шифротекст
/// суммы неотличим от шифротекста слагаемого.
///
/// Что держит сумму в группе НА САМОМ ДЕЛЕ — соотношение между нижней
/// границей ключа и тем, что вообще кодируется из `f64`. При модуле от
/// 2048 бит граница на значение равна `2^2027`, а наибольшее
/// кодируемое число — около `2^1024`: до переполнения не хватает
/// тысячи бит, то есть `2^1000` слагаемых. Это и утверждается числом в
/// `test_запас_под_сумму_перекрывает_весь_диапазон_f64`.
///
/// Счётчик при этом оставлен: он ловит вызывающего, который подаёт
/// заведомо не то, — но называть его гарантией нельзя.
const SUM_HEADROOM_TERMS: u32 = 1 << 20;

#[pyclass]
struct PublicKey {
    inner: EncryptionKey,
    /// `n` в виде `rug::Integer` — обёртка крейта наружу его не отдаёт,
    /// а нам он нужен на каждом шифровании.
    n: Integer,
    nn: Integer,
    /// `hs = h^n mod n²`. Выведено ЗДЕСЬ, а не получено извне.
    ///
    /// Проверить импортированный `hs` вычислением невозможно: проба на
    /// гладкость при границе `B` удостоверяет лишь `√B` работы, а стоит
    /// `π(B)·|n|` возведений. Вывод на месте закрывает этот класс
    /// целиком.
    ///
    /// Класс — но не всё сразу. Прежде здесь стояло «и не требует ни
    /// одной проверки чужого материала»: неверно, потому что `hs`
    /// выводится ИЗ `n`, и отравленный модуль даёт отравленный `hs`.
    /// Сам `n` проверяется в `keys::validate_public`.
    hs: Integer,
    /// Длина показателя в БАЙТАХ — половина длины модуля.
    ///
    /// Считается ОДНОЙ функцией `exponent_bytes_for` от ОДНОЙ величины
    /// — фактической длины `n`.
    ///
    /// Вынести формулу в функцию оказалось мало: аргументы остались
    /// разными. `generate_keypair` передавал запрошенные `bits`,
    /// `from_n` — `n.significant_bits()`, и при `bits = 1026` модуль
    /// выходил на 1025 бит, давая 520 байт у владельца и 512 у пира.
    /// Тест против этого был зелен потому, что стоял на `bits = 1024`,
    /// где величины совпадают случайно.
    exponent_bytes: usize,
}

#[pymethods]
impl PublicKey {
    /// Собрать открытый ключ из ОДНОГО `n`, выведя `hs` на месте.
    ///
    /// Это и есть точка, ради которой приём существует: шифрующий не
    /// получает `hs` извне и потому не обязан ему доверять. Проверить
    /// импортированный `hs` вычислением невозможно — проба на гладкость
    /// при границе `B` удостоверяет лишь `√B` работы, а стоит
    /// `π(B)·|n|` возведений.
    ///
    /// Отравленный модуль при этом даёт отравленный `hs`, сколько его
    /// ни выводи на месте, — но лечится это НЕ здесь. Проверяем то же,
    /// что все: нечётность и длину (`keys::validate_public`, там же
    /// разобрано, почему не больше). `heu` не проверяет и этого.
    ///
    /// Вывод `hs` стоит 0.030 с при `|n| = 3072`, поэтому ключ пира
    /// собирается ОДИН РАЗ и держится, а не пересобирается на сообщение.
    ///
    /// Знак `h` здесь не проверяется: для этого нужны `p` и `q`,
    /// которых у шифрующего нет. При честном `n` знак верен по
    /// построению, при нечестном — наименьшая из бед.
    #[staticmethod]
    fn from_n(py: Python<'_>, raw: &[u8]) -> PyResult<PublicKey> {
        let n = Integer::from_digits(raw, Order::MsfBe);
        if n.is_even() {
            return Err(PyValueError::new_err("modulus must be odd"));
        }
        let nn = Integer::from(&n * &n);
        let inner = EncryptionKey::from_n(Plaintext::from_rug(n.clone()));
        let hs = py
            .allow_threads(|| {
                keys::validate_public(&n)?;
                derive_hs_for(&n, None)
            })
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let exponent_bytes = exponent_bytes_for(n.significant_bits());
        Ok(PublicKey {
            inner,
            n,
            nn,
            hs,
            exponent_bytes,
        })
    }

    /// Модуль в байтах — то единственное, что уезжает к пиру.
    fn modulus_bytes(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.n.to_digits::<u8>(Order::MsfBe)).unbind()
    }

    /// Длина показателя в битах.
    ///
    /// Выведена наружу ради проверки. Судить о ней по столкновениям
    /// среди шифрований нельзя: замерено, что при 64-битном показателе
    /// совпадений среди шестисот шифрований не бывает, а стойкость там
    /// уже `2^32` — минуты работы. Проверять надо число, а не
    /// следствие.
    #[getter]
    fn exponent_bits(&self) -> usize {
        self.exponent_bytes * 8
    }

    /// Наибольший принимаемый открытый текст, в битах: `n/2`, ужатое в
    /// `SUM_HEADROOM_TERMS` раз.
    ///
    /// Выведено наружу, чтобы запас можно было проверить ЧИСЛОМ, а не
    /// подбором значения, которое проверка отвергнет. При нижней границе
    /// ключа в 2048 бит запас составляет `2^2027`, а наибольшее число,
    /// которое вообще кодируется из `f64`, — около `2^1024`: проверка
    /// диапазона при таком сочетании сработать НЕ МОЖЕТ.
    ///
    /// Она всё равно стоит, и это осознанно: длина ключа и `SCALE` —
    /// две независимые ручки, и запас между ними держится не сам собой,
    /// а вот этим неравенством. Сторожить его на месте дешевле, чем
    /// надеяться, что обе ручки всегда будут крутить вместе.
    #[getter]
    fn plaintext_bound_bits(&self) -> u32 {
        plaintext_bound(&self.n).significant_bits()
    }
}

#[pyclass]
struct SecretKey {
    inner: DecryptionKey,
    /// Свидетельство `keys::validate_private`.
    ///
    /// Поле не читается — оно существует, чтобы пропуск проверки не
    /// КОМПИЛИРОВАЛСЯ. Собрать `Validated` вне модуля `keys` нельзя, а
    /// значит нельзя собрать и `SecretKey`, не позвав проверку.
    ///
    /// Так вышло не от любви к типам. Вызов однажды исчез из
    /// `generate_keypair`, и сьют показывал 42 из 42: на честном входе
    /// ключ с проверкой и без неё одинаков. Тест на текст исходника
    /// тоже не годится — он проходит насквозь, если вызов заменить
    /// комментарием с тем же текстом, и краснеет, если вызов честно
    /// вынести в помощника. Компилятор не обманывается ни тем, ни
    /// другим.
    _validated: keys::Validated,
}

/// Кодирование float в целое.
///
/// Отказ вместо тихого нуля: `Integer::from_f64` возвращает `None` на
/// `NaN` и `±inf`, а `unwrap_or_default()` превращал их в достоверный
/// ноль, который уезжал в сумму. Пропуск в столбце признаков — штатный
/// вход, не экзотика.
fn encode(value: f64) -> Result<Plaintext, String> {
    if !value.is_finite() {
        return Err(format!(
            "value {value} is not finite: NaN and infinities have no \
             encoding, and turning them into zero would put a plausible \
             number into the sum"
        ));
    }
    let scaled = (value * SCALE).round();
    if !scaled.is_finite() {
        return Err(format!(
            "value {value:e} overflows to infinity once scaled by {SCALE:e}"
        ));
    }
    rug::Integer::from_f64(scaled)
        .map(Plaintext::from_rug)
        .ok_or_else(|| format!("value {value:e} has no integer encoding"))
}

/// Обратное к `encode`.
///
/// Отказ, а не `unwrap_or(0.0)`. Парная функция существует ровно ради
/// того, чтобы нефинитное не становилось достоверным нулём, — а здесь
/// стоял тихий ноль на любой неразобранной строке.
fn decode(m: &Plaintext) -> Result<f64, String> {
    let text = m.to_string();
    let scaled: f64 = text
        .parse()
        .map_err(|_| format!("plaintext {text} is not a decimal number"))?;
    if !scaled.is_finite() {
        return Err(format!(
            "plaintext of {} digits does not fit a float: the sum has \
             outgrown the encoding, and returning a finite number here \
             would hide that",
            text.trim_start_matches('-').len()
        ));
    }
    Ok(scaled / SCALE)
}

fn cipher_to_bytes(value: &Ciphertext) -> Vec<u8> {
    value.to_bytes_msf()
}

fn cipher_from_bytes(raw: &[u8]) -> Ciphertext {
    Ciphertext::from_bytes_msf(raw)
}

/// Наибольший принимаемый открытый текст по модулю: `n/2`, ужатое в
/// `SUM_HEADROOM_TERMS` раз.
///
/// ОДНА функция на два места — предикат шифрования и геттер. Прежде
/// формула стояла в обоих по отдельности, и мутация множителя в
/// предикате проходила сьют целиком: геттер продолжал возвращать верное
/// число, а шифрование принимало что угодно. Это ровно тот же дефект,
/// что был с длиной показателя, — и он повторился в соседней строке.
fn plaintext_bound(n: &Integer) -> Integer {
    Integer::from(n / (2u32 * SUM_HEADROOM_TERMS))
}

/// Длина показателя в байтах при модуле в `modulus_bits` бит.
///
/// Половина длины модуля. Единственное место, где эта величина
/// вычисляется: два выражения в двух местах разъезжаются молча, а
/// укорочение показателя — беззвучная потеря стойкости.
fn exponent_bytes_for(modulus_bits: u32) -> usize {
    ((modulus_bits / 2 + 7) / 8) as usize
}

/// Обёртка крейта не отдаёт `rug::Integer` наружу; через десятичную
/// строку — единственный публичный путь.
fn to_rug(value: &Plaintext) -> Integer {
    value.to_string().parse().expect("десятичная запись")
}

/// Сколько попыток подобрать годное `x`.
///
/// На честном `n` негодных значений считаные штуки, и цикл завершается
/// с первой попытки. Граница нужна потому, что цикл крутится под снятым
/// GIL: без неё зависание было бы непрерываемым.
const HS_ATTEMPTS: u32 = 64;

/// Взять случайное `x` и вывести из него `hs`.
///
/// `x` берётся из `[2, n−2]`: единица и `n−1` дают `h = −1`, и это не
/// ловится ни `gcd`, ни символом Якоби — рандомизатор при этом
/// принимает ровно два значения, а круг и гомоморфность остаются
/// верными.
fn derive_hs_for(
    n: &Integer,
    owner: Option<(&Integer, &Integer)>,
) -> Result<Integer, keys::KeyError> {
    let mut rng = rand::thread_rng();
    let width = ((n.significant_bits() + 7) / 8) as usize;
    for _ in 0..HS_ATTEMPTS {
        let mut raw = vec![0u8; width];
        rng.fill(&mut raw[..]);
        let candidate = Integer::from_digits(&raw, Order::MsfBe) % n;
        // Владелец ключа проверяет знак `h` символом Якоби; шифрующий,
        // у которого есть только `n`, этого сделать не может.
        let derived = match owner {
            Some((p, q)) => keys::derive_h_checked(&candidate, p, q, n),
            None => keys::derive_h(&candidate, n),
        };
        let h = match derived {
            Ok(h) => h,
            // Вне `[2, n−2]`, не взаимно просто, либо знак не тот —
            // берём следующее.
            Err(keys::KeyError::BadX)
            | Err(keys::KeyError::HNotAntiResidue) => continue,
            Err(other) => return Err(other),
        };
        match keys::derive_hs(&h, n) {
            Ok(hs) => return Ok(hs),
            // Нетривиальный корень из единицы: на модуль их всего
            // несколько, и это не ошибка, а редкий случай.
            Err(keys::KeyError::DegenerateHs) => continue,
            Err(other) => return Err(other),
        }
    }
    Err(keys::KeyError::NoUsableX)
}

/// `bits` — длина МОДУЛЯ `n`. Крейт по умолчанию берёт безопасные
/// простые по 1536 бит, то есть `n` на 3072 бита.
///
/// Нижняя граница проверяется ДО поиска простых, а не после. Причина не
/// в экономии: `generate_safe_prime` на восьми битах крутится вечно, и
/// крутится под снятым GIL, поэтому `SIGINT` до процесса не доходит —
/// `generate_keypair(16)` не прерывался ни Ctrl-C, ни `timeout -s INT`.
#[pyfunction]
#[pyo3(signature = (bits = 3072))]
fn generate_keypair(
    py: Python<'_>,
    bits: u32,
) -> PyResult<(PublicKey, SecretKey)> {
    if bits < keys::MIN_MODULUS_BITS {
        return Err(PyValueError::new_err(format!(
            "modulus of {bits} bits is refused: the floor is {} \
             (NIST SP 800-57 puts 112-bit strength at 2048). A shorter \
             key passes every correctness check and factors in \
             microseconds",
            keys::MIN_MODULUS_BITS
        )));
    }
    // Граница сверху нужна и здесь. Она была введена только для чужого
    // модуля, а свой оставался неограниченным: `generate_keypair(200000)`
    // жил через одиннадцать секунд и `SIGINT` его не брал — тот же
    // непрерываемый класс, ради которого вводилась граница снизу,
    // закрытый с одной стороны.
    if bits > keys::MAX_MODULUS_BITS {
        return Err(PyValueError::new_err(format!(
            "modulus of {bits} bits is refused: the ceiling is {}. \
             Generating safe primes that long takes unbounded time with \
             the GIL released, so the call could not be interrupted",
            keys::MAX_MODULUS_BITS
        )));
    }
    let dk = py
        .allow_threads(|| {
            let mut rng = rand::thread_rng();
            let half = bits / 2;
            let p = Plaintext::generate_safe_prime(&mut rng, half);
            let q = Plaintext::generate_safe_prime(&mut rng, half);
            DecryptionKey::from_primes(p, q)
        })
        .map_err(|e| PyValueError::new_err(format!("keygen: {e}")))?;
    // Проверяем то, чего крейт не утверждает: безопасность простых —
    // главное, остальное вспомогательное.
    let validated = keys::validate_private(&to_rug(dk.p()), &to_rug(dk.q()))
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let ek = dk.encryption_key().clone();
    let n = to_rug(ek.n());
    let nn = Integer::from(&n * &n);
    let p_rug = to_rug(dk.p());
    let q_rug = to_rug(dk.q());
    let hs = py
        .allow_threads(|| derive_hs_for(&n, Some((&p_rug, &q_rug))))
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    // От ФАКТИЧЕСКОЙ длины модуля, а не от запрошенной: произведение
    // двух простых по `bits/2` бит выходит и на `bits`, и на `bits−1`.
    let exponent_bytes = exponent_bytes_for(n.significant_bits());
    Ok((
        PublicKey {
            inner: ek,
            n,
            nn,
            hs,
            exponent_bytes,
        },
        SecretKey {
            inner: dk,
            _validated: validated,
        },
    ))
}

#[pyfunction]
fn encrypt_many(
    py: Python<'_>,
    pk: &PublicKey,
    values: Vec<f64>,
) -> PyResult<Vec<Py<PyBytes>>> {
    let (n, nn, hs) = (&pk.n, &pk.nn, &pk.hs);
    let width = pk.exponent_bytes;
    let bound = plaintext_bound(n);
    // `allow_threads` отпускает GIL: без него rayon не даст ничего.
    let encrypted: Result<Vec<Vec<u8>>, String> = py.allow_threads(|| {
        values
            .par_iter()
            .map(|v| -> Result<Vec<u8>, String> {
                let mut rng = rand::thread_rng();
                // Показатель короткий — половина длины модуля. Это
                // единственное место, где мы отступаем от исходной
                // схемы, и его длина не должна тихо уехать.
                let mut raw = vec![0u8; width];
                rng.fill(&mut raw[..]);
                let r = Integer::from_digits(&raw, Order::MsfBe);
                let encoded = match encode(*v) {
                    Ok(value) => value,
                    Err(message) => return Err(message),
                };
                let x = to_rug(&encoded);
                // Диапазон открытого текста: `−n/2 ≤ x ≤ n/2`, ужатый в
                // `SUM_HEADROOM_TERMS` раз под будущую сумму.
                //
                // Проверка на `n/2` есть и у крейта (`in_signed_group`,
                // `encryption_key.rs:62`), и у heu (`PlaintextBound`,
                // `encryptor.cc:38`). Переписывая шифрование, я её
                // потерял, и отказ из громкого стал беззвучным:
                // `1e300` возвращалось как `−4.8e299`.
                //
                // Но её одной мало: она поштучная, а переполняется
                // СУММА. Запас снимает и это — см. `SUM_HEADROOM_TERMS`.
                if x.clone().abs() > bound {
                    return Err(format!(
                        "plaintext {v:e} is outside the signed group of \
                         this key once room for a sum of \
                         {SUM_HEADROOM_TERMS} terms is reserved. At the \
                         2048-bit floor no f64 can reach this bound, so \
                         seeing this means the key or the scale changed"
                    ));
                }
                // `g^m = 1 + m·n` при `g = n+1` — одно умножение
                // вместо возведения в степень.
                //
                // Остаток ЕВКЛИДОВ, а не усечённый: при отрицательном
                // `x` обычный `%` в rug даёт отрицательное `a`, и
                // дальше `to_digits` пишет модуль числа, молча теряя
                // знак.
                //
                // Прежде здесь стояла ветка `if x < 0 { x += n }`. Она
                // делала то же самое, но была НЕОТЛИЧИМА никаким
                // наблюдением: её выключение оставляет и круг, и
                // гомоморфность зелёными. Причина в том, что `λ` чётна,
                // поэтому `(−1)^λ ≡ 1 (mod n²)`, и `−C` расшифровывается
                // ровно как `C`; сам `−1` — законный `n`-й вычет, так
                // что `−C` есть полноценный шифротекст того же числа.
                // Ветка, которую нельзя проверить, выглядит как
                // гарантия и ею не является; евклидов остаток даёт
                // канонический вид структурно.
                let a = Integer::from(1 + x * n).rem_euc(nn.clone());
                // `hs^r = (h^r)^n` — законный `n`-й вычет, поэтому
                // расшифровка остаётся неизменной.
                let b = hs.clone().pow_mod(&r, nn).expect("pow_mod");
                let c = (a * b) % nn;
                Ok(c.to_digits::<u8>(Order::MsfBe))
            })
            .collect()
    });
    Ok(encrypted
        .map_err(PyValueError::new_err)?
        .into_iter()
        .map(|b| PyBytes::new(py, &b).unbind())
        .collect())
}

#[pyfunction]
fn add_many(
    py: Python<'_>,
    pk: &PublicKey,
    blobs: Vec<Vec<u8>>,
) -> PyResult<Py<PyBytes>> {
    let key = &pk.inner;
    if blobs.is_empty() {
        return Err(PyValueError::new_err(
            "add_many needs at least one ciphertext: an empty sum has no \
             encryption under this key, and returning one would be a \
             ciphertext of zero that nobody asked for",
        ));
    }
    // Планка на ОДИН вызов, не гарантия: результат можно подать во
    // второй вызов, и счётчик начнётся заново. Что действительно держит
    // сумму в группе — см. `SUM_HEADROOM_TERMS`.
    if blobs.len() > SUM_HEADROOM_TERMS as usize {
        return Err(PyValueError::new_err(format!(
            "add_many takes at most {SUM_HEADROOM_TERMS} ciphertexts per \
             call, got {}: past that the reserved headroom stops covering \
             the sum. This is a per-call limit, not a guarantee - chaining \
             calls escapes it, and what actually keeps sums in range is \
             the gap between the key floor and the f64 range",
            blobs.len()
        )));
    }
    // Ошибка `oadd`, а не паника. `PanicException` наследует
    // `BaseException`, поэтому `except Exception` её НЕ ловит: соседний
    // вход того же происхождения — пустая сумма — получал аккуратный
    // `ValueError`, а неверный шифротекст ронял процесс.
    let total = py.allow_threads(|| {
        let mut iter = blobs.iter().map(|b| cipher_from_bytes(b));
        let first = iter.next().expect("проверено выше");
        iter.enumerate().try_fold(first, |acc, (index, c)| {
            key.oadd(&acc, &c).map_err(|e| {
                format!(
                    "ciphertext #{} does not belong to this key: {e}. \
                     A valid ciphertext lies in [0, n^2) and is coprime \
                     with n",
                    index + 1
                )
            })
        })
    })
    .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &cipher_to_bytes(&total)).unbind())
}

#[pyfunction]
fn decrypt(sk: &SecretKey, blob: Vec<u8>) -> PyResult<f64> {
    let c = cipher_from_bytes(&blob);
    let m = sk
        .inner
        .decrypt(&c)
        .map_err(|e| PyValueError::new_err(format!("decrypt: {e}")))?;
    decode(&m).map_err(PyValueError::new_err)
}

#[pymodule]
fn paillier(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PublicKey>()?;
    m.add_class::<SecretKey>()?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_many, m)?)?;
    m.add_function(wrap_pyfunction!(add_many, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    Ok(())
}
