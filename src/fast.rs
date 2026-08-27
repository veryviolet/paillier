//! Encryption arithmetic: a window table in Montgomery form, read in
//! constant time.
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

use rug::Integer;

use crate::mont::{Limb, Montgomery, Work};

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
/// µs per exponentiation. These are HISTORICAL — taken on `mpz`
/// arithmetic, before Montgomery form, which is why the `w = 6` row does
/// not match what `benches/exponent_length.rs` prints today (830 µs).
/// They are kept because what they justify is the CHOICE of `w`, and
/// that comparison only means anything between rows measured the same
/// way:
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
/// RAM and constant-time reading stops paying off — the read touches the
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
/// `hs^(d · 2^(WINDOW_BITS·i))`, held in MONTGOMERY FORM.
///
/// Stored as limbs of fixed width rather than as `Integer`, and that is
/// not a layout detail but the condition for constant time. Two separate
/// properties rest on it:
///
/// * selecting an entry without revealing the index means touching the
///   whole row, which needs every entry at the same offset and width;
/// * the COST of a multiplication must not depend on the value, and an
///   `Integer` shortens itself to its significant limbs while a limb
///   buffer of fixed length does not.
///
/// The second property is why the entries are in Montgomery form: it is
/// what lets the arithmetic stay on fixed-width limbs, without a
/// value-dependent division. See `crate::mont`.
///
/// It costs no extra memory: an `Integer` of 4096 bits already occupies
/// its 512 bytes plus a header.
///
/// A row is one contiguous block — `ROW_ENTRIES × width` limbs in a row
/// — so reading it is sequential rather than `2^w` jumps around the
/// heap.
///
/// 64-bit limbs rather than bytes, and the difference is entirely in the
/// cost. Reading the row is the only added work, and it is bounded by
/// the number of iterations rather than the volume: byte-wise
/// constant-time reading cost **+26 %** on the exponentiation, limb-wise
/// **+1…5 %**. That figure is historical, from when both arms of
/// `benches/window_select.rs` were `mpz` and only the selection
/// differed; its second arm now also uses Montgomery form, so it no
/// longer isolates the read.
pub struct WindowTable {
    rows: Vec<Vec<Limb>>,
    form: Montgomery,
}

impl WindowTable {
    /// The number of windows, i.e. the exponent length in digits.
    pub fn windows(&self) -> usize {
        self.rows.len()
    }

    /// Entry width in limbs — the width of `n²`.
    pub fn entry_width(&self) -> usize {
        self.form.limbs()
    }
}

/// Builds the table. It costs about `windows · (2^w − 2)` multiplications
/// plus `windows · w` squarings; at 3072 bits that is on the order of
/// five thousand operations, i.e. a fraction of a second, and they pay
/// for themselves within the first hundred encryptions.
///
/// # Montgomery form, on the second attempt
///
/// The entries used to be ordinary residues modulo `n²`. Montgomery form
/// was implemented once and REMOVED on measurement: assembled from
/// `rug::Integer` operations, REDC allocates at every step and loses by a
/// factor of 1.19. That measurement was right about what it measured and
/// wrong as a conclusion — what lost was the `mpz` layer, not the
/// algorithm. On limbs (`crate::mont`) the same algorithm wins, and it
/// also closes the last timing channel. The connection was already
/// written down in this file, as a note that the rejected technique was
/// the only known cure for the remaining leak; it took a second attempt
/// to act on it.
///
/// # The zero digit
///
/// Entry zero holds `R mod n²` — one, in Montgomery form.
///
/// It used to hold `n² + 1` rather than `1`, and the reason is worth
/// keeping because it is the same reason this file now works on limbs.
/// `n² + 1 ≡ 1 (mod n²)`, so the result is unchanged; but one is a
/// single-limb number, `mpz` multiplies by it in `O(limbs)`, and the
/// following `% n²` returns immediately. A zero window then cost almost
/// nothing and the time depended on the exponent again.
///
/// How that was caught is worth recording. The first version put `1`
/// there, and I expected a slowdown of one sixteenth. The measurement
/// showed 0.6 % instead of 6.7 %, and I read that as good news — though
/// the missing six percent WERE the work that was not being done.
/// **Cheaper than expected is not a gift. It is a signal.**
///
/// The padding is no longer needed, and not because the problem went
/// away: the buffer is fixed-width now, so no value in it is cheaper to
/// multiply by than another. `n² + 1` also forced the entry width to be
/// taken from `n² + 1` rather than `n²`, one bit wider; that goes with
/// it.
pub fn build_window_table(hs: &Integer, nn: &Integer, windows: usize) -> WindowTable {
    let form = Montgomery::new(nn).expect("n^2 is odd: n is a product of odd primes");
    let width = form.limbs();
    let mut work = Work::new(width);

    let mut rows = Vec::with_capacity(windows);
    let mut base = Integer::from(hs % nn);
    for _ in 0..windows {
        let mut row = vec![0 as Limb; ROW_ENTRIES * width];
        row[0..width].copy_from_slice(form.one());

        let mut value = base.clone();
        put(&mut row, 1, width, &form.enter(&value, &mut work));
        for entry in 2..ROW_ENTRIES {
            value = value * &base % nn;
            let in_form = form.enter(&value, &mut work);
            put(&mut row, entry, width, &in_form);
        }
        rows.push(row);

        // The base for the next window: `base^(2^WINDOW_BITS)`.
        for _ in 0..WINDOW_BITS {
            base = base.clone().square() % nn;
        }
    }
    WindowTable { rows, form }
}

/// Places one entry into a row.
fn put(row: &mut [Limb], entry: usize, width: usize, value: &[Limb]) {
    let start = entry * width;
    row[start..start + width].copy_from_slice(value);
}

/// `hs^r mod n²` from a prepared table.
///
/// A multiplication happens at EVERY window, zero digits included.
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
/// # The cache channel
///
/// The entry used to be taken by index — `table[window][digit]` — so the
/// address of the memory access depended on the secret digit. Here the
/// WHOLE row is read and the wanted entry folded out with an
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
/// Measured when BOTH arms were `mpz` and only the selection differed —
/// a historical figure, and the only one that isolates the price of the
/// mask. `benches/window_select.rs` no longer reproduces it: its new arm
/// also changed the arithmetic, so it now prints the whole difference
/// between the two states of the library: 0.85–0.95 at 2048 over eight
/// runs, 0.93–0.96 at 3072.
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
/// # The leading-zeros channel
///
/// It was open until this loop moved into Montgomery form, and this is
/// the record of it.
///
/// The loop starts from one. While the low digits of the exponent are
/// zero the accumulator stays equal to one, and an `Integer` holding one
/// occupies a single limb — so multiplying by it costs almost nothing.
/// Measured: **−6.33 µs per leading zero** at FIXED weight. The weight
/// channel was closed and the position channel was not.
///
/// The obvious cure does not work, and that was checked: starting from
/// `n² + 1` gave a slope of −6.56, because `%` returns the canonical
/// residue and after the first reduction the accumulator is one again.
/// While a value is CONGRUENT to one, it is represented as one.
///
/// What closes it is holding the accumulator in a FIXED-WIDTH limb
/// buffer, where no value is cheaper to multiply by than another. That
/// needs reduction without division, which is what Montgomery form is —
/// see `crate::mont`.
///
/// The size of what was leaking: the run of leading zeros is geometric, a
/// digit is zero with probability `q = 2^−w`, and the entropy is
/// `[−(1−q)·lg(1−q) − q·lg q] / (1−q)` — **0.118 bits** out of 1024 at
/// `w = 6`. It used to say **0.36**, the correct value for `w = 4`.
///
/// Guarded by `tests/timing_channel.rs`, which measures the slope rather
/// than trusting this paragraph.
pub fn pow_by_table(table: &WindowTable, digits: &[u8]) -> Integer {
    // A digit outside the row would yield ZERO rather than a refusal:
    // the mask would match no entry and the buffer would stay zero. Such
    // input used to blow up the indexing, i.e. it was visible at once.
    // The check costs one pass over the digits against as many
    // multiplications on 4096 bits.
    assert!(
        digits.iter().all(|digit| (*digit as usize) < ROW_ENTRIES),
        "an exponent digit does not fit a {WINDOW_BITS}-bit window"
    );
    assert!(
        digits.len() <= table.rows.len(),
        "the exponent has {} digits and the table has {} windows",
        digits.len(),
        table.rows.len()
    );

    let form = &table.form;
    let width = form.limbs();
    // Allocated per call rather than shared: encryption runs across rayon
    // threads and these buffers are mutable state. Four allocations
    // against 171 multiplications on 4096 bits.
    let mut work = Work::new(width);
    let mut selected = vec![0 as Limb; width];
    let mut product = vec![0 as Limb; width];
    let mut result = form.one().to_vec();

    for (window, digit) in digits.iter().enumerate() {
        select_entry(&table.rows[window], width, *digit, &mut selected);
        form.mul(&result, &selected, &mut product, &mut work);
        // Swap rather than copy: `mpn_mul_n` needs a destination that
        // does not overlap its operands, so the two buffers take turns.
        std::mem::swap(&mut result, &mut product);
    }
    form.leave(&result, &mut work)
}

/// Puts entry number `digit` into `out`, having read the whole row.
///
/// There is not a single branch on `digit` here: the mask comes from
/// arithmetic on `entry ^ digit`, and both alternatives always execute.
/// A comparison `entry == digit` would leave the compiler free to turn
/// it into a jump — and a jump is exactly the channel being closed.
///
/// GMP has `mpn_sec_tabselect`, which does precisely this. It is NOT
/// used, and deliberately: it would add a fifth `unsafe` call for an
/// operation that needs none. Selection is a masked read over a slice,
/// which safe Rust expresses exactly; the `unsafe` in this crate is
/// confined to the arithmetic that genuinely cannot be written without
/// it.
fn select_entry(row: &[Limb], width: usize, digit: u8, out: &mut [Limb]) {
    out.fill(0);
    for entry in 0..ROW_ENTRIES {
        // All ones when `entry == digit`, all zeros otherwise.
        let difference = (entry as u32) ^ (digit as u32);
        let is_wanted = (difference.wrapping_sub(1) >> 31) as Limb;
        let mask = 0_u64.wrapping_sub(is_wanted);
        let start = entry * width;
        for (target, source) in out.iter_mut().zip(&row[start..start + width]) {
            *target |= *source & mask;
        }
    }
}
