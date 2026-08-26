//! Время возведения не должно зависеть от ВЕСА показателя.
//!
//! Это ТЕСТ, а не прогон, и разница здесь существенная. Прежде проверка
//! жила в `benches/`, то есть запускалась только вручную и печатала
//! число, которое человек читал глазами. Ровно так и появилась
//! регрессия, которую он же и пропустил: подстановка единицы в таблицу
//! дала подорожание 0.6 % вместо ожидавшихся 6.7 %, и это прочли как
//! хорошую новость вместо признака невыполняемой работы. Ставить
//! сторожем то же самое действие — значит закрывать дефект его же
//! причиной.
//!
//! Признак — НАКЛОН времени по весу, а не абсолютное время: абсолютное
//! зависит от машины, наклон — нет. Запас: сигнал утечки был 6.1–6.3
//! мкс на цифру, шум около 0.26, порог 1.0 даёт шестикратный зазор
//! снизу и четырёхкратный сверху.

use paillier::fast::{build_window_table, pow_by_table, WindowTable};
use rug::Integer;
use std::time::Instant;

const WINDOWS: usize = 256;

/// Сколько РАЗНЫХ цифр перебирать. Прежде стояло 15 — весь диапазон при
/// четырёхбитном окне и четверть его при шестибитном. Проверка на
/// постоянство времени обязана трогать всю строку, иначе три четверти
/// записей в замер не попадают.
const ROW_SPAN: usize = 1 << paillier::fast::WINDOW_BITS;

/// Повторов на точку. Разброс между соседними замерами доходил до 15 %,
/// а сигнал утечки на всём диапазоне — около 1200 мкс; медиана из пяти
/// прогонов по тридцать убирает выбросы, не удлиняя тест заметно.
const ROUNDS: usize = 30;
const REPEATS: usize = 5;

/// Ровно `count` ненулевых цифр, РАВНОМЕРНО по всей длине.
///
/// Прежняя редакция брала `i % step == 0`, и при `count = 192` шаг
/// выходил единичным: получалось 256 ненулевых вместо 192, две точки из
/// четырёх совпадали, и наклон считался по вырожденному набору.
fn digits_with_weight(count: usize) -> Vec<u8> {
    (0..WINDOWS)
        .map(|i| {
            let before = i * count / WINDOWS;
            let after = (i + 1) * count / WINDOWS;
            if after > before {
                ((i % (ROW_SPAN - 1)) + 1) as u8
            } else {
                0
            }
        })
        .collect()
}

/// Порог наклона, мкс на цифру. Выше — утечка вернулась.
const SLOPE_LIMIT: f64 = 1.0;

/// Модуль для замера. Простые ДАЛЕКО друг от друга — не потому, что это
/// важно для времени, а чтобы фикстуру нельзя было скопировать как
/// образец ключа: близкие простые раскладываются методом Ферма, и
/// `keys::validate_private` такой ключ отвергает.
fn modulus() -> Integer {
    let mut p = (Integer::from(1) << 1024u32) + 1u32;
    p.next_prime_mut();
    let mut q = (Integer::from(1) << 900u32) + 4321u32;
    q.next_prime_mut();
    let n = Integer::from(&p * &q);
    Integer::from(&n * &n)
}

fn measure(table: &WindowTable, digits: &[u8], nn: &Integer) -> f64 {
    // Прогрев: первый вызов платит за промахи кэша.
    let _ = pow_by_table(table, digits, nn);
    let mut taken: Vec<f64> = Vec::with_capacity(REPEATS);
    for _ in 0..REPEATS {
        let started = Instant::now();
        let mut guard = Integer::from(0);
        for _ in 0..ROUNDS {
            guard += pow_by_table(table, digits, nn).significant_bits();
        }
        assert!(guard > 0);
        taken.push(started.elapsed().as_secs_f64() * 1e6 / ROUNDS as f64);
    }
    taken.sort_by(|a, b| a.partial_cmp(b).expect("время не бывает NaN"));
    taken[REPEATS / 2]
}

/// Наименьших квадратов по точкам `(цифр, мкс)`.
fn slope(points: &[(f64, f64)]) -> f64 {
    let count = points.len() as f64;
    let mean_x = points.iter().map(|p| p.0).sum::<f64>() / count;
    let mean_y = points.iter().map(|p| p.1).sum::<f64>() / count;
    let top: f64 = points.iter().map(|p| (p.0 - mean_x) * (p.1 - mean_y)).sum();
    let bottom: f64 = points.iter().map(|p| (p.0 - mean_x).powi(2)).sum();
    top / bottom
}

#[test]
fn time_does_not_depend_on_exponent_weight() {
    let nn = modulus();
    let hs = Integer::from(&nn / 3u32) + 7u32;
    let table = build_window_table(&hs, &nn, WINDOWS);

    // Ненулевые цифры РАССЕЯНЫ по всей длине, а не сдвинуты к началу:
    // иначе меняется не только вес, но и число ведущих нулей, и один
    // канал маскирует другой. Именно на этом прежняя редакция и
    // проглядела позиционную утечку.
    let mut points = Vec::new();
    for count in [64usize, 128, 192, 256] {
        let digits = digits_with_weight(count);
        let actual = digits.iter().filter(|d| **d != 0).count();
        assert_eq!(actual, count, "вес обязан быть ровно запрошенным");
        points.push((actual as f64, measure(&table, &digits, &nn)));
    }

    let found = slope(&points);
    for (count, spent) in &points {
        println!("ненулевых {count:>4} из {WINDOWS}   {spent:9.1} мкс");
    }
    println!("наклон по весу: {found:.3} мкс на цифру (порог {SLOPE_LIMIT})");

    assert!(
        found.abs() < SLOPE_LIMIT,
        "время зависит от веса показателя: наклон {found:.3} мкс на цифру. \
         Утечка в этом месте уже случалась дважды: сперва пропуском \
         нулевых цифр, потом подстановкой ОДНОЛИМБОВОЙ единицы вместо \
         полноразмерного вычета",
    );
}

#[test]
fn position_remainder_has_not_grown() {
    // Канал, который НЕ закрыт и назван в `fast::pow_by_table`: пока
    // младшие цифры нулевые, накопитель равен единице и остаётся
    // однолимбовым, поэтому ведущие нули дешевле прочих.
    //
    // Тест не требует его отсутствия — он требует, чтобы остаток не
    // РОС. Утечка на 0.118 бита допущена осознанно.
    //
    // Порог 15.0 при известном наклоне около −6.3 ловит рост в 2.4
    // раза. Здесь стояло «утечка вдесятеро больше означала бы, что
    // сломалось что-то ещё» — то есть комментарий обещал проверку
    // слабее той, что стоит в коде. Тест строже описания, вреда нет, но
    // расходиться им незачем.
    let nn = modulus();
    let hs = Integer::from(&nn / 3u32) + 7u32;
    let table = build_window_table(&hs, &nn, WINDOWS);

    let mut points = Vec::new();
    for leading in [0usize, 16, 32, 64] {
        let digits: Vec<u8> = (0..WINDOWS)
            .map(|i| if i < leading { 0 } else { ((i % (ROW_SPAN - 1)) + 1) as u8 })
            .collect();
        points.push((leading as f64, measure(&table, &digits, &nn)));
    }

    let found = slope(&points);
    for (leading, spent) in &points {
        println!("ведущих нулей {leading:>3}   {spent:9.1} мкс");
    }
    println!("наклон по позиции: {found:.3} мкс на нуль (известный остаток ~−6.3)");

    assert!(
        found.abs() < 15.0,
        "позиционный канал вырос втрое против известного: наклон {found:.3}",
    );
}
