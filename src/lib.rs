//! Paillier для Guardora: своя реализация на GMP, привязка через pyo3.
//!
//! Криптография ЗДЕСЬ, а не в зависимости: порождение безопасных
//! простых, шифрование коротким показателем, гомоморфное сложение,
//! расшифровка по китайской теореме. `fast-paillier` остался ТОЛЬКО
//! эталоном в тестах (`dev-dependencies`) — своя реализация, сверяемая
//! сама с собой, ничего не доказывает.
//!
//! Блоб = байт масштаба + шифротекст старшим байтом вперёд. Записи
//! МИНИМАЛЬНЫЕ, а не фиксированной ширины: замерено `{512: 2, 513: 398}`
//! на четырёхстах шифрованиях ключом 2048 бит. Нарезать буфер постоянным
//! шагом нельзя.
//!
//! Число здесь врало дважды. Сперва стояло `[255, 256]` — длины при
//! ключе в 1024 бита, который ниже `MIN_MODULUS_BITS` и породиться уже
//! не может. Потом `[511, 512]` — верно, но ДО введения байта масштаба,
//! то есть докстринг, описывающий формат, не знал о единственном, что
//! этот формат изменило.
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

pub mod fast;
pub mod primes;
pub mod secret;
pub mod keys;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::Rng;
use rayon::prelude::*;
use rug::integer::Order;
use rug::ops::RemRounding;
use rug::Integer;

use fast::{build_window_table, pow_by_table, windows_for, windows_of};

/// Масштаб по умолчанию: `10^8`.
///
/// Оставлен прежним намеренно. Он даёт САМЫЙ ШИРОКИЙ диапазон входа
/// (до `|v| ≈ 9e7`), а сужение диапазона ради точности — решение
/// вызывающего, который знает свои данные, а не умолчание библиотеки.
const DEFAULT_SCALE_POW10: u8 = 8;

/// Наибольший принимаемый показатель масштаба.
///
/// Выше `10^18` кодировать нечего: `2^53/10^18` меньше `1e-2`, то есть
/// точно кодируются уже только числа мельче сотой, и ошибка становится
/// относительной на всём осмысленном входе.
const MAX_SCALE_POW10: u8 = 18;

/// Масштаб кодирования float в целое: СТЕПЕНЬ ДЕСЯТКИ, едет в
/// шифротексте первым байтом.
///
/// # Почему свойство шифротекста, а не настройка
///
/// Несовпадение масштабов даёт не отказ, а правдоподобное неверное
/// число: зашифровали с `1e8`, расшифровали с `1e12` — результат меньше
/// в десять тысяч раз, конечный, без единого признака. Сложили
/// шифротексты разных масштабов — сумма бессмысленна, а различить их
/// нечем: шифротексты неотличимы.
///
/// Хуже того, у нас пассивная сторона шифрует ЧУЖИМ ключом, собирая его
/// из одного `n` (`PublicKey::from_n`). В `n` масштаба нет — значит при
/// настройке «сбоку» пир взял бы умолчание и молча разошёлся с
/// владельцем ключа.
///
/// Поэтому `decrypt` берёт масштаб ИЗ САМОГО БЛОБА, а `add_many`
/// отказывает на пачке с разными масштабами. Разойтись физически нечем.
///
/// Цена — один байт на шифротекст, 0.2 % длины.
///
/// # Округление — к ближайшему
///
/// Не усечением. Усечение к нулю смещает каждое слагаемое вниз по
/// модулю, и на ЗНАКОПОСТОЯННЫХ данных ошибка суммы растёт ЛИНЕЙНО по
/// числу слагаемых, а не как `√k`. Счётчики бакетов и квадраты
/// градиентов знакопостоянны. Замер — `benches/acc_rounding.py`.
///
/// # Два края, а не один
///
/// **Снизу.** Всё, что по модулю меньше `1/(2·10^e)`, кодируется нулём.
/// Свойство неподвижной точки, а не потеря.
///
/// **Сверху.** Ошибка равна `1/(2·10^e)` и АБСОЛЮТНА только пока
/// `|v|·10^e` представимо в f64 точно, то есть примерно до
/// `|v| ≈ 2^53/10^e`. Выше произведение округляется само, и ошибка
/// становится ОТНОСИТЕЛЬНОЙ.
///
/// | `e` | ошибка | верхняя граница `|v|` | сумма 10⁶ знакопостоянных |
/// |---|---|---|---|
/// | 8 | 5e-09 | ~9e7 | 4.69e-06 |
/// | 12 | 5e-13 | ~9e3 | **1.86e-08** |
/// | 15 | 5e-16 | ~9e0 | 1.86e-08 |
///
/// Правый столбец — ОДИН розыгрыш на строку, и читать его надо как
/// порядок, а не как величину.
///
/// Что здесь следует из механизма, а не из выборки: при `e = 12` ошибка
/// кодирования на миллионе слагаемых около `3e-10`, а расстояние между
/// соседними `f64` вблизи суммы (порядка `5e8`) — около `1.2e-07`. То
/// есть кодирование сдвигает значение меньше чем на сотую доли шага, и
/// результат почти всегда ложится на ТОТ ЖЕ float, что и точная сумма.
/// Тогда ошибка равна ПОЛУ `f64` — ошибке самого `float()` от точной
/// суммы, ниже которой не опустится никакая схема, возвращающая `f64`.
///
/// Изредка тот же крошечный сдвиг перебрасывает округление на соседний
/// float, и ошибка становится порядка шага. На трёх розыгрышах по
/// миллиону `e = 12` дал ровно пол; на четвёртом (замер ревьюера) —
/// втрое больше пола. Оба исхода нормальны и оба про округление f64, а
/// не про схему.
///
/// Здесь стояло «при `e = 12` упирается в пол» без оговорок — вывод из
/// одного розыгрыша. Верное утверждение: начиная с `e = 12` ошибка
/// схемы уходит ПОД разрешение `f64`, и увеличивать масштаб дальше
/// незачем — только диапазон сужается.
fn scale_of(pow10: u8) -> f64 {
    10f64.powi(pow10 as i32)
}

/// Проверка показателя, приехавшего снаружи или из шифротекста.
fn checked_scale(pow10: u8) -> Result<f64, String> {
    if pow10 > MAX_SCALE_POW10 {
        return Err(format!(
            "scale exponent {pow10} is above the {MAX_SCALE_POW10} this \
             encoding allows: past that even a value of one has no exact \
             f64 representation once scaled"
        ));
    }
    Ok(scale_of(pow10))
}

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
/// 2048 бит граница на значение равна `2^2026` или `2^2027`, а
/// наибольшее кодируемое число — около `2^1024`: до переполнения не
/// хватает тысячи бит, то есть `2^1000` слагаемых. Это и утверждается
/// числом в `test_запас_под_сумму_перекрывает_весь_диапазон_f64`.
///
/// Два значения, а не одно, по той же причине, что описана у
/// `MIN_MODULUS_BITS`: произведение двух простых по 1024 бита выходит
/// и на 2048 бит, и на 2047. Здесь стояло одиночное `2^2027` — и
/// каждый второй ключ его опровергал. Тест этим не задет: он считает
/// границу от ФАКТИЧЕСКОЙ длины модуля, а не сверяется с литералом.
///
/// Счётчик при этом оставлен: он ловит вызывающего, который подаёт
/// заведомо не то, — но называть его гарантией нельзя.
const SUM_HEADROOM_TERMS: u32 = 1 << 20;

#[pyclass]
struct PublicKey {
    /// `n` в виде `rug::Integer` — обёртка крейта наружу его не отдаёт,
    /// а нам он нужен на каждом шифровании.
    n: Integer,
    nn: Integer,
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
    /// Предвычисленные степени `hs` — см. `WINDOW_BITS`.
    ///
    /// Держится в ключе, а не строится на сообщение: в этом весь смысл.
    /// Ключ пира собирается один раз и живёт всю сессию, таблица вместе
    /// с ним.
    ///
    /// Само `hs` отдельным полем НЕ хранится: оно лежит первой степенью
    /// нулевого окна. Держать обе формы значило бы держать состояние,
    /// которое может разъехаться, — а `hs = h^n mod n²` выводится ЗДЕСЬ,
    /// из одного `n`, и его происхождение разобрано у `keys::derive_hs`
    /// и у `from_n`.
    ///
    /// Здесь дважды стояло утверждение о РАСПОЛОЖЕНИИ — сперва
    /// «`table[0][0]` и есть оно», потом «`table[0][1]`», — и оба раза
    /// оно переставало быть правдой молча, при правке укладки. Теперь
    /// записи вообще не индексируются снаружи: строка лежит словами и
    /// читается целиком (`fast::WindowTable`).
    table: fast::WindowTable,
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
        // Длина отсекается по СЫРЫМ БАЙТАМ, прежде чем что-либо
        // посчитано. Порядок здесь и есть предмет проверки.
        //
        // Прежде `n²` считалось до `validate_public` и вне
        // `allow_threads`. Граница `MAX_MODULUS_BITS` заведена ровно
        // против отказа в обслуживании, но стояла ПОСЛЕ самой дорогой
        // операции, и та шла с удержанным GIL. Замерено на входе от
        // пира: 64 МБ вместо модуля — 4.07 с, в течение которых
        // интерпретатор не исполняет вообще ничего, включая обработчик
        // `SIGINT`. Плюс двукратное усиление по памяти на длине,
        // которую задаёт нападающий.
        //
        // Отсев по `raw.len()` не требует даже разбора числа. Дальше
        // всё под снятым GIL.
        let limit_bytes = (keys::MAX_MODULUS_BITS as usize + 7) / 8;
        if raw.len() > limit_bytes {
            return Err(PyValueError::new_err(format!(
                "modulus of {} bytes is longer than the {limit_bytes} bytes \
                 that {} bits allow",
                raw.len(),
                keys::MAX_MODULUS_BITS,
            )));
        }
        let n = Integer::from_digits(raw, Order::MsfBe);
        if n.is_even() {
            return Err(PyValueError::new_err("modulus must be odd"));
        }
        let (nn, hs) = py
            .allow_threads(|| {
                keys::validate_public(&n)?;
                let nn = Integer::from(&n * &n);
                derive_hs_for(&n, None).map(|hs| (nn, hs))
            })
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let exponent_bytes = exponent_bytes_for(n.significant_bits());
        let table = py.allow_threads(|| build_window_table(&hs, &nn, windows_for(exponent_bytes)));
        Ok(PublicKey {
            n,
            nn,
            exponent_bytes,
            table,
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
    /// ключа в 2048 бит запас составляет `2^2026`–`2^2027` (смотря,
    /// вышло произведение простых на 2048 бит или на 2047), а
    /// наибольшее число, которое вообще кодируется из `f64`, — около
    /// `2^1024`: проверка диапазона при таком сочетании сработать
    /// НЕ МОЖЕТ.
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
    /// Расшифровка НАША, а не крейта.
    ///
    /// Крейт возводит в степень, выведенную из `λ`, через `mpz_powm`, а
    /// документация GMP для секретных показателей требует
    /// `mpz_powm_sec`. `λ` — долговременный секрет, один на весь срок
    /// ключа: утечка через него накапливается по всем расшифровкам, а
    /// не начинается заново на каждом сообщении, как было с разовым `r`.
    ///
    /// Разбор — в `secret::Decryptor`.
    inner: secret::Decryptor,
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
fn encode(value: f64, scale: f64) -> Result<Integer, String> {
    if !value.is_finite() {
        return Err(format!(
            "value {value} is not finite: NaN and infinities have no \
             encoding, and turning them into zero would put a plausible \
             number into the sum"
        ));
    }
    let scaled = (value * scale).round();
    if !scaled.is_finite() {
        return Err(format!(
            "value {value:e} overflows to infinity once scaled by {scale:e}"
        ));
    }
    Integer::from_f64(scaled)
        .ok_or_else(|| format!("value {value:e} has no integer encoding"))
}

/// Обратное к `encode`.
///
/// Отказ, а не `unwrap_or(0.0)`. Парная функция существует ровно ради
/// того, чтобы нефинитное не становилось достоверным нулём, — а здесь
/// стоял тихий ноль на любой неразобранной строке.
fn decode_integer(m: &Integer, scale: f64) -> Result<f64, String> {
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
    Ok(scaled / scale)
}

/// Разбор блоба: первый байт — показатель масштаба, остальное —
/// шифротекст старшим байтом вперёд.
///
/// Отказ, а не догадка. Пустой блоб и неизвестный показатель — это
/// вход, который НЕ является шифротекстом под этой схемой, и принимать
/// его, подставив умолчание, значило бы вернуть правдоподобное число не
/// того масштаба.
fn split_blob(blob: &[u8]) -> Result<(u8, Integer), String> {
    let (head, body) = blob.split_first().ok_or_else(|| {
        "ciphertext is empty: it must start with a scale exponent byte"
            .to_string()
    })?;
    checked_scale(*head)?;
    Ok((*head, Integer::from_digits(body, Order::MsfBe)))
}

/// Сборка блоба: показатель, затем шифротекст.
fn join_blob(pow10: u8, cipher: &Integer) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + (cipher.significant_bits() as usize + 7) / 8);
    out.push(pow10);
    out.extend_from_slice(&cipher.to_digits::<u8>(Order::MsfBe));
    out
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
    // Простые НАШИ. Прежде их давал `fast-paillier`, и числа ходили
    // оттуда через десятичную строку, потому что `Plaintext` наружу
    // `rug::Integer` не отдаёт. Ради генератора и одного `gcd` держать
    // зависимость незачем — см. `primes::safe_prime`.
    let (p_rug, q_rug) = py.allow_threads(|| {
        let half = bits / 2;
        (primes::safe_prime(half), primes::safe_prime(half))
    });
    let validated = keys::validate_private(&p_rug, &q_rug)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let n = Integer::from(&p_rug * &q_rug);
    let nn = Integer::from(&n * &n);
    let hs = py
        .allow_threads(|| derive_hs_for(&n, Some((&p_rug, &q_rug))))
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    // От ФАКТИЧЕСКОЙ длины модуля, а не от запрошенной: произведение
    // двух простых по `bits/2` бит выходит и на `bits`, и на `bits−1`.
    let exponent_bytes = exponent_bytes_for(n.significant_bits());
    let table = py.allow_threads(|| build_window_table(&hs, &nn, windows_for(exponent_bytes)));
    Ok((
        PublicKey {
            n,
            nn,
            exponent_bytes,
            table,
        },
        SecretKey {
            // Что здесь МОЖЕТ пойти не так: только `p == q` или не
            // взаимно простые. Прежде текст называл `gcd(λ, n) ≠ 1` —
            // состояние, в которое код попасть не может: расшифровка по
            // китайской теореме `λ` и `µ` не вычисляет вовсе. Ключ
            // `p = 23, q = 47`, у которого `µ` не существует и который
            // библиотека dfns отвергает, наш расшифровщик принимает и
            // расшифровывает верно — проверено на 101 значении из 101.
            inner: secret::Decryptor::new(&p_rug, &q_rug).ok_or_else(|| {
                PyValueError::new_err(
                    "cannot prepare decryption: the two primes are equal \
                     or not coprime, so the CRT split does not exist",
                )
            })?,
            _validated: validated,
        },
    ))
}

#[pyfunction]
#[pyo3(signature = (pk, values, scale_pow10 = DEFAULT_SCALE_POW10))]
fn encrypt_many(
    py: Python<'_>,
    pk: &PublicKey,
    values: Vec<f64>,
    scale_pow10: u8,
) -> PyResult<Vec<Py<PyBytes>>> {
    let (n, nn, table) = (&pk.n, &pk.nn, &pk.table);
    let width = pk.exponent_bytes;
    let bound = plaintext_bound(n);
    let scale = checked_scale(scale_pow10).map_err(PyValueError::new_err)?;
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
                // Показатель никогда не собирается в `Integer`: цифры
                // окон читаются прямо из байт генератора. Собирать было
                // бы не только лишней работой — это ещё и второе место,
                // где длина показателя могла бы разъехаться.
                let digits = windows_of(&raw);
                let encoded = match encode(*v, scale) {
                    Ok(value) => value,
                    Err(message) => return Err(message),
                };
                let x = encoded;
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
                //
                // По ТАБЛИЦЕ, а не `pow_mod`: основание фиксировано на
                // весь ключ, и его степени уже посчитаны. `pow_mod`
                // строил бы свою таблицу заново на каждое сообщение.
                let b = pow_by_table(table, &digits, nn);
                let c = (a * b) % nn;
                Ok(join_blob(scale_pow10, &c))
            })
            .collect()
    });
    Ok(encrypted
        .map_err(PyValueError::new_err)?
        .into_iter()
        .map(|b| PyBytes::new(py, &b).unbind())
        .collect())
}

/// Шифротексты принимаются как `PyBytes`, а НЕ как `Vec<Vec<u8>>`.
///
/// Разница не косметическая, она измерена. При `Vec<Vec<u8>>` pyo3
/// разбирает каждый `bytes` через протокол последовательности —
/// побайтно, через питоновские целые. На 512-байтных шифротекстах это
/// пять миллионов операций на десять тысяч слагаемых.
///
/// Замерено: копия цикла `add_many` на Rust идёт 7.36 мкс на слагаемое,
/// а сам `add_many` из Python показывал 85. Все недостающие 78 мкс
/// уходили сюда, ДО единой операции по модулю. Через `PyBytes` берётся
/// готовый срез.
///
/// Разбор при этом честно искали заменой приёма: сперва я снял `gcd` из
/// `oadd`, решив, что дело в нём, — не помогло ни на что. Правильный
/// ответ дал различающий замер: цикл против цикла.
#[pyfunction]
fn add_many(
    py: Python<'_>,
    pk: &PublicKey,
    blobs: Vec<Bound<'_, PyBytes>>,
) -> PyResult<Py<PyBytes>> {
    let nn = &pk.nn;
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
    // Срезы, а НЕ копии: `as_bytes` заимствует буфер самого `bytes`.
    // Прежде здесь стояло «копия — обычный memcpy», и это было неверным
    // обоснованием верного кода.
    //
    // Почему снятие GIL всё же безопасно: `blobs` держит `Bound`-ссылки
    // живыми на всё время вызова, а `bytes` в Python неизменяемы —
    // значит буфер не сдвинется и не перепишется под нами.
    let slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_bytes()).collect();

    // Ошибка, а не паника. `PanicException` наследует `BaseException`,
    // поэтому `except Exception` её НЕ ловит: соседний вход того же
    // происхождения — пустая сумма — получал аккуратный `ValueError`, а
    // неверный шифротекст ронял процесс.
    //
    // Умножение считается ЗДЕСЬ, а не через `oadd` крейта: тот проверяет
    // на принадлежность группе ОБОИХ операндов, то есть накопитель
    // проходит `gcd` заново на каждом слагаемом.
    //
    // Проверка та же, что у heu (`VALIDATE`, `decryptor.cc:20`):
    // шифротекст обязан лежать в `[1, n²)`. Сравнение вместо `gcd`.
    // Ноль отвергается отдельно — он необратим, то есть шифротекстом не
    // является ни при каком открытом тексте.
    //
    // Чего эта проверка НЕ делает, в отличие от прежнего `oadd`: она не
    // ловит НЕОБРАТИМЫЙ шифротекст. Значение `n` попадает в `[1, n²)`,
    // но `gcd(n, n²) ≠ 1`, и сумма с ним испортится. Отказ тогда придёт
    // позже и без адреса — у владельца при `decrypt`, общим «decryption
    // error» вместо номера слагаемого. Это осознанный паритет с heu: у
    // них `VALIDATE` тоже проверяет только диапазон, а `gcd` на каждом
    // слагаемом стоил бы дороже всей операции.
    let (total, scale_pow10) = py
        .allow_threads(|| {
            let mut total = Integer::from(1);
            let mut scale_pow10: Option<u8> = None;
            for (index, blob) in slices.iter().enumerate() {
                let (pow10, value) = split_blob(blob)
                    .map_err(|message| format!("ciphertext #{}: {message}", index + 1))?;
                // Складывать шифротексты разных масштабов — значит
                // складывать разные единицы измерения. Схема этого не
                // видит: коды целые, сумма получится, и вернётся
                // правдоподобное неверное число. Поэтому ОТКАЗ, а не
                // приведение к общему масштабу: привести можно только
                // умножением открытого текста, а он зашифрован.
                match scale_pow10 {
                    None => scale_pow10 = Some(pow10),
                    Some(first) if first != pow10 => {
                        return Err(format!(
                            "ciphertext #{} was encoded with scale 1e{pow10} \
                             while the sum started at 1e{first}: adding them \
                             would produce a plausible wrong number, and \
                             rescaling is impossible on encrypted values",
                            index + 1
                        ))
                    }
                    Some(_) => {}
                }
                if value < 1 || value >= *nn {
                    return Err(format!(
                        "ciphertext #{} is not in [1, n^2) of this key: a \
                         valid ciphertext is an invertible residue modulo \
                         n^2, and this one is not",
                        index + 1
                    ));
                }
                total = total * value % nn;
            }
            Ok((total, scale_pow10.expect("пачка не пуста — проверено выше")))
        })
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &join_blob(scale_pow10, &total)).unbind())
}

#[pyfunction]
fn decrypt(sk: &SecretKey, blob: &[u8]) -> PyResult<f64> {
    let (scale_pow10, cipher) = split_blob(blob).map_err(PyValueError::new_err)?;
    let scale = scale_of(scale_pow10);
    let plain = sk.inner.decrypt(&cipher).ok_or_else(|| {
        PyValueError::new_err(
            "not a ciphertext under this key: a valid one lies in \
             [1, n^2) and is coprime with n. A ciphertext made under a \
             different key usually lands here, but not always - there is \
             no pairing check, and there cannot be one from n alone",
        )
    })?;
    decode_integer(&plain, scale).map_err(PyValueError::new_err)
}

#[pymodule]
fn paillier(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Версия берётся из `Cargo.toml` на СБОРКЕ, а не переписывается
    // руками: две копии числа разъезжаются молча, и разъехавшаяся
    // версия хуже отсутствующей — она врёт про то, какой код в
    // `site-packages`. Модуль кладётся туда файлом, без метаданных
    // пакета, поэтому спросить `importlib.metadata` не у кого.
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<PublicKey>()?;
    m.add_class::<SecretKey>()?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_many, m)?)?;
    m.add_function(wrap_pyfunction!(add_many, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    Ok(())
}
