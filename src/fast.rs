//! Encryption arithmetic: a window table with constant-time reading.
//!
//! Split out of `lib.rs` not for tidiness but for testability. While
//! these were private functions, a test could only ASSEMBLE A COPY of
//! them from the description — and would then be checking an
//! implementation against itself. Now the test calls the real code, and
//! the reference is `pow_mod` from GMP, an independent implementation of
//! the same exponentiation.
//!
//! The technique is purely arithmetic: it does not change the result,
//! only the speed. So what has to be checked is EQUALITY of results, not
//! a round trip — a round trip would stay green on a broken table if the
//! error were the same in encryption and decryption.

use rug::integer::Order;
use rug::Integer;

/// Window width of the table of precomputed powers of `hs`, in bits.
///
/// This is possible precisely because the base is fixed: `hs` does not
/// change for the whole life of the key, so its powers are computed
/// ONCE.
///
/// What it buys. `mpz_powm` on a 1024-bit exponent does about 1024
/// squarings plus 170 multiplications and REBUILDS ITS OWN TABLE on
/// every call — it does not survive the return. With a ready table one
/// multiplication per window is left: 171 operations instead of ~1200.
///
/// Exactly 171, not "168 on average": zero digits are no longer skipped,
/// because skipping made the time depend on the secret exponent. The
/// analysis is at `pow_by_table`.
///
/// # Why six
///
/// Encryption is 98 % multiplications in `pow_by_table`, and the number
/// of multiplications equals the number of windows — `⌈|r| / w⌉`.
/// Measured at `|n| = 2048`, 1024-bit exponent, constant-time reading,
/// µs per exponentiation:
///
/// | `w` | windows | table | time |
/// |---|---|---|---|
/// | 4 | 256 | 2.1 MB | 1517–1603 |
/// | **6** | **171** | **5.6 MB** | **976–1022** |
/// | 8 | 128 | 16.8 MB | 761–793 |
/// | 10 | 103 | 54 MB | 694–743 |
///
/// Six is where the gain is still nearly linear in the window count
/// while the table stays comfortably below the level-3 cache (16 MB on
/// this machine). At `w = 8` the table sits right on that boundary and
/// the number starts depending on the hardware; at `w = 10` it lives in
/// RAM and constant-time reading stops paying off — the mask reads the
/// WHOLE row, so it doubles in cost with every extra bit.
///
/// Memory is not an abstraction here: the table is built per peer key
/// and lives for the whole session. 5.6 MB at 2048 bits, 12.6 at 3072.
///
/// This used to say `w = 4`, next to a calculation showing `w = 5` would
/// give "19.8 % for 7.6 MB". That calculation counted only
/// multiplications and ignored that the cost of a multiplication does
/// not depend on `w` at all while the cost of reading grows: what had to
/// be compared was measured time, not an operation count.
pub const WINDOW_BITS: u32 = 6;

/// Entries per row: `2^WINDOW_BITS`.
const ROW_ENTRIES: usize = 1usize << WINDOW_BITS;

/// How many windows an exponent of `bytes` bytes needs.
///
/// One function for every place that needs this number: the table build
/// and the exponent split have to agree, and pairs like that drift apart
/// silently. This used to be `bytes * 2` in two places — correct for
/// `w = 4` exactly and wrong for anything else.
pub fn windows_for(bytes: usize) -> usize {
    (bytes * 8 + WINDOW_BITS as usize - 1) / WINDOW_BITS as usize
}

/// Digits of the exponent, least significant first, `WINDOW_BITS` wide.
///
/// Read straight out of the bytes the random generator produced — no
/// `Integer` assembled, no shifting back. The bytes are most
/// significant first (`Order::MsfBe`), so bit `i` (counting from the
/// bottom) lives in byte `raw[len − 1 − i/8]`.
///
/// Digits used to be cut out as nibbles — `byte & 0x0f`, `byte >> 4` —
/// which works only while `WINDOW_BITS = 4`. At six bits a digit crosses
/// a byte boundary, so the split has to go bit by bit.
///
/// There is no branch on VALUES here: the loop bounds are set by the
/// exponent length, which is public.
pub fn windows_of(raw: &[u8]) -> Vec<u8> {
    let bits = raw.len() * 8;
    let width = WINDOW_BITS as usize;
    let mut out = Vec::with_capacity(windows_for(raw.len()));
    let mut index = 0usize;
    while index < bits {
        let mut digit = 0u8;
        for offset in 0..width {
            let bit_index = index + offset;
            if bit_index >= bits {
                break;
            }
            let byte = raw[raw.len() - 1 - bit_index / 8];
            digit |= ((byte >> (bit_index % 8)) & 1) << offset;
        }
        out.push(digit);
        index += width;
    }
    out
}

/// Precomputed powers of `hs`: entry `[i][d]` equals
/// `hs^(d · 2^(WINDOW_BITS·i))`.
///
/// Stored as WORDS of fixed width rather than as `Integer`, and that is
/// not a layout detail but the condition for constant time: selecting an
/// entry without revealing the index is only possible by reading the
/// whole row and folding it with a mask. Such a read cannot be written
/// over `Integer` — their lengths differ, and GMP's operations cut
/// corners on short values.
///
/// It costs no extra memory: an `Integer` of 4096 bits already occupies
/// its 512 bytes plus a header.
///
/// A row is one contiguous block — `ROW_ENTRIES × width` words in a row
/// — so reading it is sequential rather than `2^w` jumps around the
/// heap.
///
/// 64-bit words rather than bytes, and the difference is entirely in the
/// cost. Reading the row is the only added work, and it is bounded by
/// the number of iterations rather than the volume: byte-wise
/// constant-time reading cost **+26 %** on the exponentiation, word-wise
/// **+1…5 %** (measured at 2048 and 3072 bits,
/// `benches/window_select.rs`).
pub struct WindowTable {
    rows: Vec<Vec<u64>>,
    width: usize,
}

impl WindowTable {
    /// The number of windows, i.e. the exponent length in digits.
    pub fn windows(&self) -> usize {
        self.rows.len()
    }

    /// Entry width in 64-bit words — the width of `n²`.
    pub fn entry_width(&self) -> usize {
        self.width
    }
}

/// Builds the table. It costs about `windows · (2^w − 2)` multiplications
/// plus `windows · w` squarings; at 3072 bits that is on the order of
/// five thousand operations, i.e. a fraction of a second, and they pay
/// for themselves within the first hundred encryptions.
///
/// The entries are ordinary residues modulo `n²`, WITHOUT Montgomery
/// space. That was implemented here and removed on measurement: REDC
/// over `rug::Integer` is assembled from the same full-width operations
/// with an allocation at every step, and loses by a factor of 1.19.
///
/// # The zero digit is stored as `n² + 1`, NOT as `1`
///
/// `n² + 1 ≡ 1 (mod n²)`, so the result is the same. But one is a
/// single-limb number: GMP computes `result * 1` in `O(limbs)`, and the
/// following `% n²` returns immediately because the product is already
/// below the modulus. A zero window then costs almost nothing, and the
/// time depends on the exponent AGAIN — that is, substituting one does
/// not close the leak.
///
/// How this was caught is worth recording. The first version put `1`
/// there, and I expected a slowdown of one sixteenth. The measurement
/// showed 0.6 % instead of 6.7 %, and I read that as good news — though
/// the missing six percent WERE the work that was not being done.
/// **Cheaper than expected is not a gift. It is a signal.**
///
/// `n² + 1` is one bit wider than `n²`, so the entry width is taken from
/// `n² + 1` rather than from `n²`: otherwise the top bit of the zero
/// digit would be cut off and it would become a zero.
pub fn build_window_table(
    hs: &Integer,
    nn: &Integer,
    windows: usize,
) -> WindowTable {
    let one_mod_nn = Integer::from(nn + 1u32);
    let width = ((one_mod_nn.significant_bits() as usize) + 63) / 64;
    let mut rows = Vec::with_capacity(windows);
    let mut base = hs.clone();
    for _ in 0..windows {
        let mut row = vec![0u64; ROW_ENTRIES * width];
        put(&mut row, 0, width, &one_mod_nn);
        let mut value = base.clone();
        put(&mut row, 1, width, &value);
        for entry in 2..ROW_ENTRIES {
            value = value * &base % nn;
            put(&mut row, entry, width, &value);
        }
        rows.push(row);
        // The base for the next window: `base^(2^WINDOW_BITS)`.
        for _ in 0..WINDOW_BITS {
            base = base.clone().square() % nn;
        }
    }
    WindowTable { rows, width }
}

/// Places a number into a row entry, zero-padded on the left.
///
/// `write_digits` fills the whole slice rather than only the significant
/// words — otherwise the entry width would depend on the value, and
/// constant time would be lost in the very place it is built.
fn put(row: &mut [u64], entry: usize, width: usize, value: &Integer) {
    let start = entry * width;
    value.write_digits(&mut row[start..start + width], Order::LsfLe);
}

/// `hs^r mod n²` from a prepared table.
///
/// A multiplication happens at EVERY window, zero digits included: the
/// table holds `n² + 1` there — a full-width residue equal to one modulo
/// `n²`. Why that rather than `1` is explained at `build_window_table`.
///
/// Zero digits used to be skipped, so the number of multiplications
/// equalled the number of non-zero nibbles of the SECRET exponent.
/// Measured at `|n| = 2048`: from 0.2 µs on an empty exponent to 1576 µs
/// on a full one, linear, at 6.1 µs per digit — 0.4 % of the total time,
/// far above the noise. An observer watching the clock learns the weight
/// of `r`.
///
/// Did that breach the claimed margin? No: exact knowledge of the weight
/// gives about four bits out of 1024, the strong form (which digits are
/// zero) about 86, and it stays far above the `2^512` bound. But "does
/// not breach" and "is safe" are different statements — exactly the
/// substitution of "correct" for "secure" that
/// `docs/short-exponent-security.md` is written against.
///
/// (Those two figures are at `WINDOW_BITS = 4`, when there were 256
/// windows. At six bits the weight is distributed as
/// `Binomial(171, 1/64)` and its entropy is about 2.7 bits, not four.
/// The paragraph is kept as HISTORY of a closed channel and marked so it
/// is not read as the current state.)
///
/// # The cache channel is closed, and its cost had been computed wrong
///
/// The entry used to be taken by index — `table[window][digit]` — so the
/// address of the memory access depended on the secret digit. Here the
/// WHOLE row is read and the wanted entry is selected with an
/// all-ones/all-zeros mask computed by arithmetic, with no branch. An
/// observer watching cache accesses sees the same sequence of addresses
/// for any exponent.
///
/// It stayed open because of a number, and the number was wrong. The
/// docstring said: "closing it would mean reading the whole row at every
/// window, i.e. paying sixteen times over". That conflates "read sixteen
/// entries" with "do sixteen multiplications". There is still exactly
/// ONE multiplication; what is added is a streaming read of eight
/// kilobytes, which against a 4096-bit multiplication costs almost
/// nothing.
///
/// Measured (`benches/window_select.rs`, both layouts on the same `hs`,
/// `n²` and exponent, results checked for equality):
///
/// | `|n|` | rows | by index | by mask | ratio |
/// |---|---|---|---|---|
/// | 2048 | 171 | 1061 µs | 1019 µs | **0.96** |
/// | 3072 | 256 | 2842 µs | 2946 µs | **1.04** |
///
/// Not sixteen times over but a few percent either way — inside machine
/// noise. The number the decision to leave the channel open rested on
/// was inflated by more than an order of magnitude.
///
/// An unstated premise worth stating. Constant time here rests on every
/// entry occupying FULL `width` words. Reading the row respects that,
/// but `assign_digits` strips leading zero words — an entry with a zero
/// top word would make the following `mpz_mul` slightly cheaper. The
/// probability of that, for `hs^k mod n²` uniform, is about `2^−64` per
/// entry, so it is not a channel; but the property rests on that
/// estimate, not only on the shape of the loop.
///
/// # What is NOT closed
///
/// **Leading zeros.** The loop starts from `result = 1`, and while the
/// low digits are zero the accumulator stays single-limb — multiplying
/// by it costs almost nothing. Measured: **−6.33 µs per leading zero**
/// at FIXED weight. So the weight channel is closed and the position
/// channel is not.
///
/// The obvious cure does not work, and that was checked: starting from
/// `n² + 1` gives a slope of −6.56, because `%` returns the canonical
/// residue and after the first reduction the accumulator is one again.
/// While a value is CONGRUENT to one, it is represented as one.
///
/// The only known cure is a redundant representation in which one is not
/// single-limb — that is, Montgomery form. It was rejected on speed, and
/// the connection is worth naming plainly: **the rejected technique is
/// the only known cure for the remaining channel.**
///
/// The size of the remainder: the run of leading zeros is geometric, a
/// digit is zero with probability `q = 2^−w`, and the entropy is
/// `[−(1−q)·lg(1−q) − q·lg q] / (1−q)`.
///
/// At `w = 6` that is **0.118 bits** out of 1024. It used to say
/// **0.36** — the correct value for `w = 4`, where `q = 1/16`. This
/// number is a DIRECT consequence of the window width, and widening the
/// window from four bits to six cut the leak threefold without touching
/// a line of this loop. It is the only quantity in the repository that
/// describes an OPEN channel — so it has to follow from the code rather
/// than survive an edit to it.
///
/// Against a `2^512` margin it is nothing, and the remainder is accepted
/// knowingly. It is guarded by
/// `tests/timing_channel.rs::position_remainder_has_not_grown` — not for
/// absence, but for not growing.
pub fn pow_by_table(
    table: &WindowTable,
    digits: &[u8],
    nn: &Integer,
) -> Integer {
    // A digit outside the row would yield ZERO rather than a refusal:
    // the mask would match no entry and `out` would stay zero. Such
    // input used to blow up the indexing, i.e. it was visible at once.
    // The check costs one pass over the digits against as many
    // multiplications on 4096 bits.
    assert!(
        digits.iter().all(|digit| (*digit as usize) < ROW_ENTRIES),
        "an exponent digit does not fit a {WINDOW_BITS}-bit window"
    );
    let width = table.width;
    let mut selected = vec![0u64; width];
    // Both numbers are created ONCE and reused: `assign_digits` and the
    // in-place operations allocate nothing, whereas `from_digits` and
    // `a * b % m` allocate two objects per window — five hundred-odd
    // times per encryption.
    let mut entry = Integer::new();
    let mut result = Integer::from(1);
    for (window, digit) in digits.iter().enumerate() {
        select_entry(&table.rows[window], width, *digit, &mut selected);
        entry.assign_digits(&selected, Order::LsfLe);
        result *= &entry;
        result %= nn;
    }
    result
}

/// Puts entry number `digit` into `out`, having read the whole row.
///
/// There is not a single branch on `digit` here: the mask comes from
/// arithmetic on `entry ^ digit`, and both alternatives always execute.
/// A comparison `entry == digit` would leave the compiler free to turn
/// it into a jump — and a jump is exactly the channel being closed.
fn select_entry(row: &[u64], width: usize, digit: u8, out: &mut [u64]) {
    out.fill(0);
    for entry in 0..ROW_ENTRIES {
        // All ones when `entry == digit`, all zeros otherwise.
        let difference = (entry as u32) ^ (digit as u32);
        let is_wanted = (difference.wrapping_sub(1) >> 31) as u64;
        let mask = 0u64.wrapping_sub(is_wanted);
        let start = entry * width;
        for (target, source) in out.iter_mut().zip(&row[start..start + width]) {
            *target |= *source & mask;
        }
    }
}
