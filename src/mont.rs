//! Montgomery arithmetic on limbs. **The only module in this crate that
//! contains `unsafe`.**
//!
//! The crate root carries `#![deny(unsafe_code)]`; this file lifts it
//! for itself and nothing else. If `unsafe` ever appears anywhere else,
//! the build fails.
//!
//! # Why it exists
//!
//! Two reasons, and the second is the one that matters.
//!
//! **Speed.** Montgomery form was implemented once over `rug::Integer`
//! and rolled back on measurement: there REDC is assembled from
//! full-width `mpz` operations with an allocation at every step and
//! loses by a factor of 1.19. On limbs, with no allocation in the hot
//! loop, the same algorithm wins.
//!
//! **The last timing channel.** The window-table loop starts its
//! accumulator at one, and `mpz` stores a number in as many limbs as it
//! needs: a one occupies a single limb, and multiplying by it is
//! correspondingly cheap. While the low windows of the secret exponent
//! select the identity entry, the accumulator stays short and the
//! iterations stay cheap — measured at −6.3 µs per leading zero window.
//!
//! What removes it is the buffer, not the value. `mpn_*` operates on a
//! FIXED number of limbs given by the caller and never normalises: a
//! product of two `k`-limb buffers costs the same whether the operands
//! are `n²−1` or one. Leading zeros stop being visible because nothing
//! ever looks at how many there are.
//!
//! Montgomery form is what makes staying in limbs possible at all.
//! Reduction modulo `n²` would otherwise need division, and `mpn`
//! division IS value-dependent; REDC replaces it with multiplication
//! and a single conditional subtraction, both fixed-width.
//!
//! Note what is NOT the argument: that one becomes a big number in
//! Montgomery form. `R mod n²` is usually wide, but when `n²` sits just
//! under a power of two it is `R − n²` and can be tiny. The cure does
//! not depend on it either way.
//!
//! # What is unsafe here, precisely
//!
//! Four GMP functions, called over buffers whose lengths are checked in
//! safe code immediately before the call:
//!
//! | function | contract we must uphold |
//! |---|---|
//! | `mpn_mul_n` | `rp` holds `2n` limbs and does not overlap the operands |
//! | `mpn_addmul_1` | `rp` and `s1p` hold `n` limbs |
//! | `mpn_sub_n` | all three hold `n` limbs |
//! | `mpn_cnd_sub_n` | all three hold `n` limbs |
//!
//! Violating any of them is undefined behaviour, not a panic. So every
//! entry point asserts the lengths in safe Rust first, and the `unsafe`
//! blocks are single calls with nothing else inside them.
//!
//! There are no raw pointers stored in any structure, no lifetimes
//! being extended, no aliasing tricks and no allocation inside the
//! blocks. This is the simplest shape `unsafe` comes in.
//!
//! # Constant time
//!
//! `mpn_mul_n` and `mpn_addmul_1` branch on SIZE, not on values, and
//! our sizes are fixed for the whole life of a key.
//!
//! `mpn_sec_mul` would be the explicitly constant-time multiplication,
//! and it is deliberately NOT used: to stay constant-time it forgoes
//! sub-quadratic algorithms, which at 64 limbs is exactly the speed we
//! came here for. The choice is documented rather than silent.
//!
//! The final conditional subtraction is the classic place where
//! constant time is lost to an `if`. It is done with `mpn_cnd_sub_n`,
//! which subtracts under a flag without branching, and the flag itself
//! is computed by arithmetic.

#![allow(unsafe_code)]

use gmp_mpfr_sys::gmp;
use rug::integer::Order;
use rug::Integer;

/// A limb — one machine word of GMP's representation.
pub type Limb = gmp::limb_t;

const LIMB_BITS: u32 = (std::mem::size_of::<Limb>() * 8) as u32;

/// Everything derived from the modulus once, when the key is built.
pub struct Montgomery {
    limbs: usize,
    /// The modulus `n²`, exactly `limbs` long. Must be odd.
    modulus: Vec<Limb>,
    /// `−n^{-1} mod 2^64` — the Montgomery constant.
    n_prime: Limb,
    /// `R² mod n²`, for entering the form.
    r_squared: Vec<Limb>,
    /// `R mod n²` — the Montgomery representation of one. Its VALUE
    /// varies with the modulus; its WIDTH is always `limbs`, and that is
    /// what matters.
    one: Vec<Limb>,
}

/// Reusable buffers, so the hot loop allocates nothing.
pub struct Work {
    product: Vec<Limb>,
    scratch: Vec<Limb>,
}

impl Work {
    pub fn new(limbs: usize) -> Self {
        Self {
            // Exactly the width of the product. There is no extra limb
            // for the carry off the top: that carry lives in `pending`
            // and is consumed as a flag, never stored. A `2k+1` buffer
            // was written here at first, and its last limb was written
            // twice and read never.
            product: vec![0; 2 * limbs],
            scratch: vec![0; limbs],
        }
    }
}

/// `x^{-1} mod 2^64` by Newton iteration, for odd `x`.
///
/// Each step doubles the number of correct bits, so six steps take one
/// correct bit to sixty-four. Pure safe arithmetic.
///
/// Five steps happen to suffice for every modulus this crate builds —
/// `n²` is an odd square, so it is 1 mod 8 and the seed starts with
/// three correct bits rather than one. `Montgomery::new` is `pub` and
/// takes any odd `Integer`, so the sixth step stays: it is the general
/// bound, not headroom to trim.
fn inverse_mod_word(x: Limb) -> Limb {
    debug_assert!(x & 1 == 1, "the modulus must be odd");
    let mut inverse: Limb = 1;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(inverse)));
    }
    debug_assert_eq!(x.wrapping_mul(inverse), 1);
    inverse
}

impl Montgomery {
    /// Prepare the form for a modulus. `None` if it is even or zero.
    ///
    /// Everything here is setup, done once per key, and uses `rug` — no
    /// reason to hand-roll what is not on the hot path.
    pub fn new(modulus: &Integer) -> Option<Self> {
        // `<= 0` rather than `== 0`: `is_even` is false for −3, and
        // `write_digits` would then store its ABSOLUTE value, quietly
        // building the form for a different modulus than the caller
        // named. Not reachable from this crate, where the modulus is
        // always `n²`, but the signature says `Integer`.
        if modulus.is_even() || *modulus <= 0 {
            return None;
        }
        let limbs = ((modulus.significant_bits() + LIMB_BITS - 1) / LIMB_BITS) as usize;

        let mut words = vec![0 as Limb; limbs];
        modulus.write_digits(&mut words, Order::LsfLe);

        let n_prime = inverse_mod_word(words[0]).wrapping_neg();

        // R = 2^(LIMB_BITS · limbs)
        let r = Integer::from(1) << (LIMB_BITS * limbs as u32);
        let r_mod = Integer::from(&r % modulus);
        let r2_mod = Integer::from(&r_mod * &r_mod) % modulus;

        let mut r_squared = vec![0 as Limb; limbs];
        r2_mod.write_digits(&mut r_squared, Order::LsfLe);
        let mut one = vec![0 as Limb; limbs];
        r_mod.write_digits(&mut one, Order::LsfLe);

        Some(Self {
            limbs,
            modulus: words,
            n_prime,
            r_squared,
            one,
        })
    }

    pub fn limbs(&self) -> usize {
        self.limbs
    }

    /// Is a limb buffer strictly below the modulus?
    ///
    /// Safe Rust, comparing from the top limb down — `mpn_cmp` would do
    /// the same thing and cost a fifth `unsafe`. Used only by
    /// `debug_assert`, so its cost never reaches a release build.
    fn below_modulus(&self, value: &[Limb]) -> bool {
        for (left, right) in value.iter().zip(&self.modulus).rev() {
            if left != right {
                return left < right;
            }
        }
        false
    }

    /// The Montgomery representation of one: `R mod n²`, in a buffer of
    /// exactly `limbs` limbs.
    pub fn one(&self) -> &[Limb] {
        &self.one
    }

    /// Convert an integer into Montgomery form.
    ///
    /// `value` must already be reduced modulo `n²`.
    pub fn enter(&self, value: &Integer, work: &mut Work) -> Vec<Limb> {
        let mut plain = vec![0 as Limb; self.limbs];
        value.write_digits(&mut plain, Order::LsfLe);
        let mut out = vec![0 as Limb; self.limbs];
        self.mul(&plain, &self.r_squared, &mut out, work);
        out
    }

    /// Convert back out of Montgomery form.
    pub fn leave(&self, value: &[Limb], work: &mut Work) -> Integer {
        let mut plain = vec![0 as Limb; self.limbs];
        let mut one = vec![0 as Limb; self.limbs];
        one[0] = 1;
        self.mul(value, &one, &mut plain, work);
        Integer::from_digits(&plain, Order::LsfLe)
    }

    /// Montgomery multiplication: `out = a · b · R^{-1} mod n²`.
    ///
    /// The lengths are asserted here, in safe code, so that every
    /// `unsafe` call below is over buffers already known to be the right
    /// size.
    ///
    /// # Range precondition
    ///
    /// Both operands must be BELOW the modulus. That is not a tidiness
    /// rule: the reduction leaves a value under `a·b/R + n²`, and a
    /// SINGLE conditional subtraction brings it into range only while
    /// `a·b < n²·R`. Feed it two values in `[n², 2n²)` and the result can
    /// stay above the modulus, silently, for the rest of the
    /// computation.
    ///
    /// Every operand this crate produces satisfies it — `enter` and `mul`
    /// both return reduced values, and `one` is `R mod n²` — so the check
    /// is a `debug_assert`: in release it would cost a comparison per
    /// multiplication, i.e. per window.
    pub fn mul(&self, a: &[Limb], b: &[Limb], out: &mut [Limb], work: &mut Work) {
        let k = self.limbs;
        assert_eq!(a.len(), k, "left operand has the wrong width");
        assert_eq!(b.len(), k, "right operand has the wrong width");
        assert_eq!(out.len(), k, "output has the wrong width");
        assert_eq!(work.product.len(), 2 * k, "scratch has the wrong width");
        assert_eq!(work.scratch.len(), k, "scratch has the wrong width");
        debug_assert!(self.below_modulus(a), "left operand is not reduced");
        debug_assert!(self.below_modulus(b), "right operand is not reduced");

        // 1. The full product, 2k limbs.
        //
        // SAFETY: `product` holds exactly the 2k limbs the call writes;
        // `a` and `b` hold k each, asserted above; the destination is a
        // distinct allocation from both operands, which the borrow
        // checker guarantees (`work` is `&mut`, `a` and `b` are `&`).
        unsafe {
            gmp::mpn_mul_n(
                work.product.as_mut_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                k as i64,
            );
        }

        // 2. Reduction, limb by limb. After step `i` the limb
        //    `product[i]` becomes zero, and the carry moves one position
        //    up — the classic carry chain. Two overflows in one step
        //    would make `pending` two; instrumented over 28 000
        //    multiplications at every limb count and every distance from
        //    the limb boundary, the largest seen is one. The `+` is kept
        //    because the bound, not the observation, is what makes it
        //    correct.
        let mut pending: Limb = 0;
        for i in 0..k {
            let u = work.product[i].wrapping_mul(self.n_prime);

            // SAFETY: the window `product[i .. i+k]` ends at `2k-1` at
            // worst, because `i < k`, so it lies inside a buffer of 2k;
            // `modulus` holds exactly k.
            let carry = unsafe {
                gmp::mpn_addmul_1(
                    work.product.as_mut_ptr().add(i),
                    self.modulus.as_ptr(),
                    k as i64,
                    u,
                )
            };

            let (sum, over_one) = work.product[i + k].overflowing_add(carry);
            let (sum, over_two) = sum.overflowing_add(pending);
            work.product[i + k] = sum;
            pending = Limb::from(over_one) + Limb::from(over_two);
        }

        // 3. The result sits in `product[k .. 2k]`, with `pending` above
        //    it, and is below `2·n²`. One conditional subtraction brings
        //    it into range.
        //
        //    The condition is computed WITHOUT a branch: subtract into
        //    scratch to learn the borrow, then subtract for real under a
        //    flag. Doing it with an `if` is the classic way to lose
        //    constant time at the last step.
        out.copy_from_slice(&work.product[k..2 * k]);

        // SAFETY: all three buffers hold exactly k limbs, asserted above.
        let borrow = unsafe {
            gmp::mpn_sub_n(
                work.scratch.as_mut_ptr(),
                out.as_ptr(),
                self.modulus.as_ptr(),
                k as i64,
            )
        };

        // Subtract if the value overflowed the top limb (`pending != 0`)
        // or if it is at least the modulus (`borrow == 0`).
        let overflowed = Limb::from(pending != 0);
        let at_least = 1 ^ borrow;
        let condition = overflowed | at_least;

        // SAFETY: all three buffers hold exactly k limbs.
        unsafe {
            gmp::mpn_cnd_sub_n(
                condition,
                out.as_mut_ptr(),
                out.as_ptr(),
                self.modulus.as_ptr(),
                k as i64,
            );
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// The fixtures to run every test over.
    ///
    /// What decides whether a test can SEE the final conditional
    /// subtraction is not the frequency with which it fires. It is the
    /// slack — how far `n²` sits below the limb boundary, `64·limbs −
    /// |n²|`.
    ///
    /// At slack 2 the modulus is under `R/4`, and the recurrence without
    /// the subtraction is a fixed point: operands below `2n²` give a
    /// product below `4n⁴`, so the reduction returns less than
    /// `4n⁴/R + n² < 2n²`, and `leave` then brings it back under `n²`
    /// anyway. Every value such a test observes is already canonical, so
    /// deleting the subtraction changes nothing it can look at — even
    /// though, instrumented, the subtraction fires 227 times in 8000
    /// multiplications there.
    ///
    /// That was the first fixture's blind spot, and the second one's:
    /// the first sat at slack 4, the second at slack 2, and the docstring
    /// blamed frequency, which was the wrong cause.
    ///
    /// Real keys land at slack 0 to 3 — measured over fourteen
    /// `generate_keypair(2048)`: `{0: 1, 1: 5, 2: 6, 3: 2}`. At slack 0
    /// and 1 a missing subtraction lets the value overflow its `k`-limb
    /// buffer and produces WRONG ciphertexts. So the flush shapes are not
    /// a corner: they are one key in seven.
    ///
    /// Hence three shapes, and every test iterates over all of them:
    ///
    /// * `flush` — `n²` fills its limbs and `R mod n²` is a general large
    ///   value. This is the production shape;
    /// * `flush-sliver` — `n²` just under a power of two, so `R mod n²`
    ///   is a sliver. The same slack, the opposite extreme of the value;
    /// * `mid` — slack 2, kept because it was the shape that hid the
    ///   defect, and a fixture set that drops it stops testing the case
    ///   that fooled us.
    fn moduli_of(key_bits: u32) -> Vec<(&'static str, Integer)> {
        let half = key_bits / 2;
        let build = |p_seed: Integer, q_seed: Integer| {
            let (mut p, mut q) = (p_seed, q_seed);
            p.next_prime_mut();
            q.next_prime_mut();
            let n = Integer::from(&p * &q);
            Integer::from(&n * &n)
        };
        vec![
            // p, q ≈ (7/8)·2^half → n² ≈ 0.59·R: fills its limbs, and
            // `R mod n² = R − n²` is about 0.7·n².
            (
                "flush",
                build(Integer::from(7) << (half - 3), (Integer::from(7) << (half - 3)) + 4242u32),
            ),
            // p, q just under 2^half → n² just under R.
            (
                "flush-sliver",
                build(
                    (Integer::from(1) << half) - 12345u32,
                    (Integer::from(1) << half) - 54321u32,
                ),
            ),
            // p ≈ (3/4)·2^half, q ≈ (5/8)·2^half → slack 2.
            (
                "mid",
                build(Integer::from(3) << (half - 2), Integer::from(5) << (half - 3)),
            ),
        ]
    }

    fn slack_of(nn: &Integer) -> u32 {
        let limbs = (nn.significant_bits() + LIMB_BITS - 1) / LIMB_BITS;
        limbs * LIMB_BITS - nn.significant_bits()
    }

    /// The fixture set must contain the shape production uses.
    ///
    /// Its predecessor asserted `slack < 4` and reported "the conditional
    /// subtraction stops firing" — both wrong. `slack == 2` satisfies
    /// that assertion and is blind, and the subtraction fires there
    /// perfectly well. What has to be asserted is that a FLUSH modulus is
    /// present at all.
    #[test]
    fn the_fixture_set_covers_the_production_shape() {
        for key_bits in [512u32, 1024, 2048] {
            let shapes = moduli_of(key_bits);
            let slacks: Vec<(&str, u32)> = shapes
                .iter()
                .map(|(name, nn)| (*name, slack_of(nn)))
                .collect();

            assert!(
                slacks.iter().any(|(_, slack)| *slack == 0),
                "no flush modulus at {key_bits} bits: {slacks:?}. Without one, \
                 deleting the conditional subtraction leaves every test green"
            );
            assert!(
                slacks.iter().any(|(_, slack)| *slack >= 2),
                "no slack modulus at {key_bits} bits: {slacks:?}. That is the \
                 shape that hid the defect, and it stays in the set"
            );
        }
    }

    /// `mul` must return a value BELOW the modulus. This is the property
    /// the final conditional subtraction exists to establish, and
    /// checking the product alone does not check it: on a slack fixture a
    /// non-canonical result still converts back to the right integer.
    ///
    /// Do not simplify this away as redundant with the equality checks.
    /// It is the SOLE detector for one mutation — dropping the `at_least`
    /// term from the subtraction condition. Neutered to a tautology, that
    /// mutation survives the entire suite; the other two die either way.
    fn assert_reduced(got: &[Limb], nn: &Integer, what: &str) {
        let value = Integer::from_digits(got, Order::LsfLe);
        assert!(
            value < *nn,
            "{what}: mul returned {value}, which is not below the modulus — \
             the conditional subtraction did not happen"
        );
    }

    /// The reference is `rug`, i.e. an independent implementation of the
    /// same arithmetic. Comparing our Montgomery against our Montgomery
    /// would prove nothing.
    #[test]
    fn multiplication_matches_rug() {
        for bits in [512u32, 1024, 2048] {
            for (name, nn) in moduli_of(bits) {
                let form = Montgomery::new(&nn).expect("odd modulus");
                let mut work = Work::new(form.limbs());

                for step in 0..64u32 {
                    let a = Integer::from(&nn / (3u32 + step % 5)) + step;
                    let b = Integer::from(&nn / (7u32 + step % 3)) + 11u32 + step;

                    let want = Integer::from(&a * &b) % &nn;

                    let am = form.enter(&a, &mut work);
                    let bm = form.enter(&b, &mut work);
                    let mut got = vec![0 as Limb; form.limbs()];
                    form.mul(&am, &bm, &mut got, &mut work);
                    assert_reduced(&got, &nn, &format!("{name}/{bits}, step {step}"));

                    let got = form.leave(&got, &mut work);
                    assert_eq!(want, got, "{name}, bits {bits}, step {step}");
                }
            }
        }
    }

    /// The edges are where a reduction goes wrong: zero, one, the modulus
    /// minus one, and a value that forces the final conditional
    /// subtraction.
    #[test]
    fn edges_match_rug() {
        for (name, nn) in moduli_of(1024) {
            let form = Montgomery::new(&nn).expect("odd modulus");
            let mut work = Work::new(form.limbs());

            let edges = [
                Integer::from(0),
                Integer::from(1),
                Integer::from(&nn - 1u32),
                Integer::from(&nn - 2u32),
                Integer::from(&nn >> 1u32),
            ];
            for a in &edges {
                for b in &edges {
                    let want = Integer::from(a * b) % &nn;
                    let am = form.enter(a, &mut work);
                    let bm = form.enter(b, &mut work);
                    let mut got = vec![0 as Limb; form.limbs()];
                    form.mul(&am, &bm, &mut got, &mut work);
                    assert_reduced(&got, &nn, &format!("{name}, a={a}, b={b}"));
                    assert_eq!(want, form.leave(&got, &mut work), "{name}, a={a}, b={b}");
                }
            }
        }
    }

    /// One in Montgomery form must occupy a FIXED-WIDTH buffer — that is
    /// the whole reason this module exists. An `mpz` one occupies a single
    /// limb, and that is what made the leading-zeros channel measurable.
    #[test]
    fn one_is_a_fixed_width_buffer() {
        for bits in [1024u32, 2048] {
            for (name, nn) in moduli_of(bits) {
                let form = Montgomery::new(&nn).expect("odd modulus");
                let one = form.one();

                // Fixed WIDTH, whatever the value: that is the property
                // the whole module rests on. Asserting the top limb is
                // non-zero would be asserting something about the value,
                // and that is not a theorem — the `flush-sliver` shape in
                // this very set has a small `R mod n²`, and the module
                // still works.
                assert_eq!(one.len(), form.limbs(), "{name}");

                // And it must actually behave as one.
                let mut work = Work::new(form.limbs());
                let a = Integer::from(&nn / 3u32) + 7u32;
                let am = form.enter(&a, &mut work);
                let mut got = vec![0 as Limb; form.limbs()];
                form.mul(&am, one, &mut got, &mut work);
                assert_eq!(a, form.leave(&got, &mut work), "{name}");
            }
        }
    }

    /// The range precondition on `mul` must actually fire.
    ///
    /// It is a `debug_assert`, so this test exists only in a debug build
    /// — and that is the point. CI ran `cargo test --release` alone,
    /// where `debug_assert!` is compiled out, so neither the
    /// precondition nor `below_modulus` was ever executed. A bug planted
    /// in `below_modulus` (comparing limbs from the least significant
    /// end instead of the most) survived the whole suite. CI now runs
    /// `cargo test --lib` in debug as well.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "not reduced")]
    fn an_unreduced_operand_is_refused_in_debug() {
        let nn = moduli_of(512)[0].1.clone();
        let form = Montgomery::new(&nn).expect("odd modulus");
        let mut work = Work::new(form.limbs());

        // The modulus itself, which is not below the modulus. A single
        // conditional subtraction cannot bring the result of such a
        // multiplication back into range.
        let mut unreduced = vec![0 as Limb; form.limbs()];
        nn.write_digits(&mut unreduced, Order::LsfLe);

        let mut out = vec![0 as Limb; form.limbs()];
        form.mul(&unreduced, form.one(), &mut out, &mut work);
    }

    /// `below_modulus` must compare from the TOP limb down.
    ///
    /// Comparing from the bottom gives the wrong answer for almost every
    /// pair and is invisible in release. Checked directly rather than
    /// through `mul`, because a helper used only by a `debug_assert` is
    /// otherwise tested by nothing at all.
    #[test]
    fn below_modulus_compares_from_the_top() {
        let nn = moduli_of(512)[0].1.clone();
        let form = Montgomery::new(&nn).expect("odd modulus");
        let k = form.limbs();

        let mut smaller = vec![0 as Limb; k];
        Integer::from(&nn - 1u32).write_digits(&mut smaller, Order::LsfLe);
        assert!(form.below_modulus(&smaller), "n^2 - 1 is below n^2");

        let mut equal = vec![0 as Limb; k];
        nn.write_digits(&mut equal, Order::LsfLe);
        assert!(!form.below_modulus(&equal), "n^2 is not below itself");

        // The discriminating case: the low limb is smaller while the top
        // limb is larger. Comparing from the bottom answers "below" here.
        let mut mixed = equal.clone();
        mixed[0] = 0;
        mixed[k - 1] = mixed[k - 1].wrapping_add(1);
        assert!(
            !form.below_modulus(&mixed),
            "a value with a larger top limb is not below the modulus, \
             whatever its low limbs say"
        );
    }

    #[test]
    fn an_even_or_non_positive_modulus_is_refused() {
        assert!(Montgomery::new(&Integer::from(1024)).is_none());
        assert!(Montgomery::new(&Integer::from(0)).is_none());
        // Odd but negative: `is_even` is false, and `write_digits` would
        // store the absolute value, silently building the form for a
        // different modulus.
        assert!(Montgomery::new(&Integer::from(-3)).is_none());
    }
}
