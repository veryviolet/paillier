//! Пробная привязка Paillier к Python: fast-paillier + pyo3.
//!
//! Криптографию не пишем — она в крейте. Здесь только склейка:
//! кодирование float в целое, сериализация в фиксированные байты и
//! параллельное шифрование.
//!
//! Бэкенд `rug` выбран не по вкусу: бэкенд `num-bigint`, включённый в
//! крейте по умолчанию, тянет `glass_pumpkin`, а тот — `core2`, у
//! которого **все** версии отозваны автором. С `backend-rug` этой
//! цепочки нет вовсе, и он же считает на GMP.

pub mod keys;

use fast_paillier::{Ciphertext, DecryptionKey, EncryptionKey, Plaintext};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rayon::prelude::*;

/// Масштаб кодирования float в целое. Тот же, что в нашем текущем коде.
const SCALE: f64 = 1e8;

#[pyclass]
struct PublicKey {
    inner: EncryptionKey,
}

#[pyclass]
struct SecretKey {
    inner: DecryptionKey,
}

/// `fast_paillier` работает со ЗНАКОВОЙ группой `(-n/2, n/2)`, поэтому
/// отрицательные значения передаются как есть — загонять их в верхнюю
/// половину модуля не нужно.
fn encode(value: f64) -> Plaintext {
    let scaled = (value * SCALE).round();
    Plaintext::from_rug(rug::Integer::from_f64(scaled).unwrap_or_default())
}

fn decode(m: &Plaintext) -> f64 {
    // У обёртки есть `to_string`; через десятичную строку знак
    // сохраняется без обращения к приватному типу знака.
    let text = m.to_string();
    text.parse::<f64>().unwrap_or(0.0) / SCALE
}

/// Шифротекст всегда положителен и лежит в `Z*_{n²}`, поэтому знак
/// хранить не нужно — в отличие от открытого текста.
fn cipher_to_bytes(value: &Ciphertext) -> Vec<u8> {
    value.to_bytes_msf()
}

fn cipher_from_bytes(raw: &[u8]) -> Ciphertext {
    Ciphertext::from_bytes_msf(raw)
}

/// `bits` — длина МОДУЛЯ n. Крейт по умолчанию берёт безопасные
/// простые по 1536 бит, то есть n на 3072 бита; для сравнения с
/// библиотеками на 2048 нужны простые по 1024.
#[pyfunction]
#[pyo3(signature = (bits = 3072))]
fn generate_keypair(py: Python<'_>, bits: u32) -> PyResult<(PublicKey, SecretKey)> {
    let dk = py.allow_threads(|| {
        let mut rng = rand::thread_rng();
        let half = bits / 2;
        let p = Plaintext::generate_safe_prime(&mut rng, half);
        let q = Plaintext::generate_safe_prime(&mut rng, half);
        DecryptionKey::from_primes(p, q)
    })
    .map_err(|e| PyValueError::new_err(format!("keygen: {e}")))?;
    let ek = dk.encryption_key().clone();
    Ok((PublicKey { inner: ek }, SecretKey { inner: dk }))
}

#[pyfunction]
fn encrypt_many(
    py: Python<'_>,
    pk: &PublicKey,
    values: Vec<f64>,
) -> PyResult<Vec<Py<PyBytes>>> {
    let key = &pk.inner;
    // `allow_threads` отпускает GIL: без него rayon не даст ничего.
    let encrypted: Vec<Vec<u8>> = py.allow_threads(|| {
        values
            .par_iter()
            .map(|v| {
                let mut rng = rand::thread_rng();
                let m = encode(*v);
                let (c, _nonce) =
                    key.encrypt_with_random(&mut rng, &m).expect("encrypt");
                cipher_to_bytes(&c)
            })
            .collect()
    });
    Ok(encrypted
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
    let total = py.allow_threads(|| {
        let mut iter = blobs.iter().map(|b| cipher_from_bytes(b));
        let first = iter.next().expect("empty");
        iter.fold(first, |acc, c| key.oadd(&acc, &c).expect("oadd"))
    });
    Ok(PyBytes::new(py, &cipher_to_bytes(&total)).unbind())
}

#[pyfunction]
fn decrypt(sk: &SecretKey, blob: Vec<u8>) -> PyResult<f64> {
    let c = cipher_from_bytes(&blob);
    let m = sk
        .inner
        .decrypt(&c)
        .map_err(|e| PyValueError::new_err(format!("decrypt: {e}")))?;
    Ok(decode(&m))
}

#[pymodule]
fn rustpaillier(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PublicKey>()?;
    m.add_class::<SecretKey>()?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_many, m)?)?;
    m.add_function(wrap_pyfunction!(add_many, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    Ok(())
}
