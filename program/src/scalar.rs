//! Fast sBPFv3-native Ristretto255 scalar field arithmetic (`mod L`) using 9 radix-29 limbs
//! in Montgomery representation (`a * R mod L`, `R = 2^261`).
//!
//! All intermediate sums inside `mul_limbs` and `montgomery_reduce` are bounded strictly
//! below `2^62` (`9 * (2^29 - 1)^2 < 2^62 < u64::MAX`), so `wrapping_add` is mathematically
//! overflow-free while eliminating ~180 redundant overflow branches per scalar multiply on sBPF.

use core::ops::{Add, Mul, Neg, Sub};

/// Ristretto255 group order `L = 2^252 + 27742317777372353535851937790883648493` (little-endian).
const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10,
];

const MASK29: u32 = (1u32 << 29) - 1;

/// `L` in 9 radix-29 limbs.
const L: [u32; 9] = [
    0x1cf5d3ed, 0x009318d2, 0x1de73596, 0x1df3bd45, 0x0000014d, 0x00000000, 0x00000000, 0x00000000,
    0x00100000,
];

/// `-L^{-1} mod 2^29`.
const LFACTOR: u32 = 0x12547e1b;

/// `R = 2^261 mod L` (equals `1` in Montgomery form).
const R: [u32; 9] = [
    0x114df9ed, 0x1a617303, 0x0f7c098c, 0x16793167, 0x1ffd656e, 0x1fffffff, 0x1fffffff, 0x1fffffff,
    0x000fffff,
];

/// `R^2 mod L`.
const RR: [u32; 9] = [
    0x0b5f9d12, 0x1e141b17, 0x158d7f3d, 0x143f3757, 0x1972d781, 0x042feb7c, 0x1ceec73d, 0x1e184d1e,
    0x0005046d,
];

#[inline(always)]
fn m(x: u32, y: u32) -> u64 {
    (x as u64).wrapping_mul(y as u64)
}

#[inline(always)]
fn add_limbs(a: &[u32; 9], b: &[u32; 9]) -> [u32; 9] {
    let mut sum = [0u32; 9];
    let mut carry: u32 = 0;
    let mut i = 0;
    while i < 9 {
        carry = a[i].wrapping_add(b[i]).wrapping_add(carry >> 29);
        sum[i] = carry & MASK29;
        i += 1;
    }
    sub_limbs(&sum, &L)
}

#[inline(always)]
fn sub_limbs(a: &[u32; 9], b: &[u32; 9]) -> [u32; 9] {
    let mut diff = [0u32; 9];
    let mut borrow: u32 = 0;
    let mut i = 0;
    while i < 9 {
        borrow = a[i].wrapping_sub(b[i].wrapping_add(borrow >> 31));
        diff[i] = borrow & MASK29;
        i += 1;
    }
    if (borrow >> 31) != 0 {
        let mut carry: u32 = 0;
        let mut j = 0;
        while j < 9 {
            carry = (carry >> 29).wrapping_add(diff[j]).wrapping_add(L[j]);
            diff[j] = carry & MASK29;
            j += 1;
        }
    }
    diff
}

/// Schoolbook 9x9 product in radix-29 (`max term = 9 * (2^29 - 1)^2 < 2^62`, overflow-free).
#[inline(always)]
fn mul_limbs(a: &[u32; 9], b: &[u32; 9]) -> [u64; 17] {
    let mut z = [0u64; 17];
    let mut i = 0;
    while i < 9 {
        let ai = a[i];
        z[i] = z[i].wrapping_add(m(ai, b[0]));
        z[i + 1] = z[i + 1].wrapping_add(m(ai, b[1]));
        z[i + 2] = z[i + 2].wrapping_add(m(ai, b[2]));
        z[i + 3] = z[i + 3].wrapping_add(m(ai, b[3]));
        z[i + 4] = z[i + 4].wrapping_add(m(ai, b[4]));
        z[i + 5] = z[i + 5].wrapping_add(m(ai, b[5]));
        z[i + 6] = z[i + 6].wrapping_add(m(ai, b[6]));
        z[i + 7] = z[i + 7].wrapping_add(m(ai, b[7]));
        z[i + 8] = z[i + 8].wrapping_add(m(ai, b[8]));
        i += 1;
    }
    z
}

#[inline(always)]
fn montgomery_reduce(limbs: &[u64; 17]) -> [u32; 9] {
    #[inline(always)]
    fn part1(sum: u64) -> (u64, u32) {
        let p = (sum as u32).wrapping_mul(LFACTOR) & MASK29;
        (sum.wrapping_add(m(p, L[0])) >> 29, p)
    }
    #[inline(always)]
    fn part2(sum: u64) -> (u64, u32) {
        (sum >> 29, (sum as u32) & MASK29)
    }

    // l[5], l[6], l[7] are zero, skipping 24 products automatically.
    let (c, n0) = part1(limbs[0]);
    let (c, n1) = part1(c.wrapping_add(limbs[1]).wrapping_add(m(n0, L[1])));
    let (c, n2) = part1(
        c.wrapping_add(limbs[2])
            .wrapping_add(m(n0, L[2]))
            .wrapping_add(m(n1, L[1])),
    );
    let (c, n3) = part1(
        c.wrapping_add(limbs[3])
            .wrapping_add(m(n0, L[3]))
            .wrapping_add(m(n1, L[2]))
            .wrapping_add(m(n2, L[1])),
    );
    let (c, n4) = part1(
        c.wrapping_add(limbs[4])
            .wrapping_add(m(n0, L[4]))
            .wrapping_add(m(n1, L[3]))
            .wrapping_add(m(n2, L[2]))
            .wrapping_add(m(n3, L[1])),
    );
    let (c, n5) = part1(
        c.wrapping_add(limbs[5])
            .wrapping_add(m(n1, L[4]))
            .wrapping_add(m(n2, L[3]))
            .wrapping_add(m(n3, L[2]))
            .wrapping_add(m(n4, L[1])),
    );
    let (c, n6) = part1(
        c.wrapping_add(limbs[6])
            .wrapping_add(m(n2, L[4]))
            .wrapping_add(m(n3, L[3]))
            .wrapping_add(m(n4, L[2]))
            .wrapping_add(m(n5, L[1])),
    );
    let (c, n7) = part1(
        c.wrapping_add(limbs[7])
            .wrapping_add(m(n3, L[4]))
            .wrapping_add(m(n4, L[3]))
            .wrapping_add(m(n5, L[2]))
            .wrapping_add(m(n6, L[1])),
    );
    let (c, n8) = part1(
        c.wrapping_add(limbs[8])
            .wrapping_add(m(n0, L[8]))
            .wrapping_add(m(n4, L[4]))
            .wrapping_add(m(n5, L[3]))
            .wrapping_add(m(n6, L[2]))
            .wrapping_add(m(n7, L[1])),
    );

    let (c, r0) = part2(
        c.wrapping_add(limbs[9])
            .wrapping_add(m(n1, L[8]))
            .wrapping_add(m(n5, L[4]))
            .wrapping_add(m(n6, L[3]))
            .wrapping_add(m(n7, L[2]))
            .wrapping_add(m(n8, L[1])),
    );
    let (c, r1) = part2(
        c.wrapping_add(limbs[10])
            .wrapping_add(m(n2, L[8]))
            .wrapping_add(m(n6, L[4]))
            .wrapping_add(m(n7, L[3]))
            .wrapping_add(m(n8, L[2])),
    );
    let (c, r2) = part2(
        c.wrapping_add(limbs[11])
            .wrapping_add(m(n3, L[8]))
            .wrapping_add(m(n7, L[4]))
            .wrapping_add(m(n8, L[3])),
    );
    let (c, r3) = part2(
        c.wrapping_add(limbs[12])
            .wrapping_add(m(n4, L[8]))
            .wrapping_add(m(n8, L[4])),
    );
    let (c, r4) = part2(c.wrapping_add(limbs[13]).wrapping_add(m(n5, L[8])));
    let (c, r5) = part2(c.wrapping_add(limbs[14]).wrapping_add(m(n6, L[8])));
    let (c, r6) = part2(c.wrapping_add(limbs[15]).wrapping_add(m(n7, L[8])));
    let (c, r7) = part2(c.wrapping_add(limbs[16]).wrapping_add(m(n8, L[8])));
    let r8 = c as u32;

    sub_limbs(&[r0, r1, r2, r3, r4, r5, r6, r7, r8], &L)
}

#[inline(never)]
fn mont_mul(a: &[u32; 9], b: &[u32; 9]) -> [u32; 9] {
    montgomery_reduce(&mul_limbs(a, b))
}

#[inline]
fn unpack_32(bytes: &[u8; 32]) -> [u32; 9] {
    let mut w = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        w[i] = u32::from_le_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
        i += 1;
    }
    let top_mask = (1u32 << 24) - 1;
    [
        w[0] & MASK29,
        ((w[0] >> 29) | (w[1] << 3)) & MASK29,
        ((w[1] >> 26) | (w[2] << 6)) & MASK29,
        ((w[2] >> 23) | (w[3] << 9)) & MASK29,
        ((w[3] >> 20) | (w[4] << 12)) & MASK29,
        ((w[4] >> 17) | (w[5] << 15)) & MASK29,
        ((w[5] >> 14) | (w[6] << 18)) & MASK29,
        ((w[6] >> 11) | (w[7] << 21)) & MASK29,
        (w[7] >> 8) & top_mask,
    ]
}

#[inline]
fn pack_32(s: &[u32; 9]) -> [u8; 32] {
    [
        (s[0]) as u8,
        (s[0] >> 8) as u8,
        (s[0] >> 16) as u8,
        ((s[0] >> 24) | (s[1] << 5)) as u8,
        (s[1] >> 3) as u8,
        (s[1] >> 11) as u8,
        (s[1] >> 19) as u8,
        ((s[1] >> 27) | (s[2] << 2)) as u8,
        (s[2] >> 6) as u8,
        (s[2] >> 14) as u8,
        ((s[2] >> 22) | (s[3] << 7)) as u8,
        (s[3] >> 1) as u8,
        (s[3] >> 9) as u8,
        (s[3] >> 17) as u8,
        ((s[3] >> 25) | (s[4] << 4)) as u8,
        (s[4] >> 4) as u8,
        (s[4] >> 12) as u8,
        (s[4] >> 20) as u8,
        ((s[4] >> 28) | (s[5] << 1)) as u8,
        (s[5] >> 7) as u8,
        (s[5] >> 15) as u8,
        ((s[5] >> 23) | (s[6] << 6)) as u8,
        (s[6] >> 2) as u8,
        (s[6] >> 10) as u8,
        (s[6] >> 18) as u8,
        ((s[6] >> 26) | (s[7] << 3)) as u8,
        (s[7] >> 5) as u8,
        (s[7] >> 13) as u8,
        (s[7] >> 21) as u8,
        (s[8]) as u8,
        (s[8] >> 8) as u8,
        (s[8] >> 16) as u8,
    ]
}

/// Non-Montgomery canonical limb representation (`x mod L`), used so that
/// `mont_mul(x, y * R) = x * y (mod L)` directly produces packed normal bytes
/// in a single Montgomery step (cutting per-ring-slot scalar work in half).
#[derive(Copy, Clone)]
pub struct NormalScalar([u32; 9]);

/// Scalar element stored in Montgomery form (`x * R mod L`).
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Scalar([u32; 9]);

impl Scalar {
    pub const ZERO: Self = Self([0; 9]);
    pub const ONE: Self = Self(R);

    /// Convert out of Montgomery form into `NormalScalar` once outside a hot loop.
    #[inline]
    pub fn to_normal(self) -> NormalScalar {
        let mut limbs = [0u64; 17];
        let mut i = 0;
        while i < 9 {
            limbs[i] = self.0[i] as u64;
            i += 1;
        }
        NormalScalar(montgomery_reduce(&limbs))
    }

    /// Compute `(self * rhs_normal) mod L` directly as packed 32-byte little-endian scalar
    /// using a single `mont_mul` (`(self_m * rhs_n) / R = self * rhs`).
    #[inline]
    pub fn mul_normal_to_bytes(self, rhs_normal: &NormalScalar) -> [u8; 32] {
        let norm = mont_mul(&self.0, &rhs_normal.0);
        pack_32(&norm)
    }

    /// Parse a canonical little-endian 32-byte scalar strictly `< L`.
    #[inline]
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Option<Self> {
        let mut i = 32;
        while i > 0 {
            i -= 1;
            if bytes[i] < L_BYTES[i] {
                let raw = unpack_32(&bytes);
                return Some(Self(mont_mul(&raw, &RR)));
            }
            if bytes[i] > L_BYTES[i] {
                return None;
            }
        }
        None
    }

    /// Reduce a 64-byte uniform hash modulo `L`, returning Montgomery form.
    pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        let mut w = [0u32; 16];
        let mut i = 0;
        while i < 16 {
            w[i] = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            i += 1;
        }
        let lo = [
            w[0] & MASK29,
            ((w[0] >> 29) | (w[1] << 3)) & MASK29,
            ((w[1] >> 26) | (w[2] << 6)) & MASK29,
            ((w[2] >> 23) | (w[3] << 9)) & MASK29,
            ((w[3] >> 20) | (w[4] << 12)) & MASK29,
            ((w[4] >> 17) | (w[5] << 15)) & MASK29,
            ((w[5] >> 14) | (w[6] << 18)) & MASK29,
            ((w[6] >> 11) | (w[7] << 21)) & MASK29,
            ((w[7] >> 8) | (w[8] << 24)) & MASK29,
        ];
        let hi = [
            ((w[8] >> 5) | (w[9] << 27)) & MASK29,
            (w[9] >> 2) & MASK29,
            ((w[9] >> 31) | (w[10] << 1)) & MASK29,
            ((w[10] >> 28) | (w[11] << 4)) & MASK29,
            ((w[11] >> 25) | (w[12] << 7)) & MASK29,
            ((w[12] >> 22) | (w[13] << 10)) & MASK29,
            ((w[13] >> 19) | (w[14] << 13)) & MASK29,
            ((w[14] >> 16) | (w[15] << 16)) & MASK29,
            w[15] >> 13,
        ];
        let lo_n = mont_mul(&lo, &R);
        let hi_n = mont_mul(&hi, &RR);
        let norm = add_limbs(&hi_n, &lo_n);
        Self(mont_mul(&norm, &RR))
    }

    /// Convert out of Montgomery form to canonical little-endian 32-byte representation.
    #[inline]
    pub fn to_bytes(self) -> [u8; 32] {
        let mut limbs = [0u64; 17];
        let mut i = 0;
        while i < 9 {
            limbs[i] = self.0[i] as u64;
            i += 1;
        }
        let norm = montgomery_reduce(&limbs);
        pack_32(&norm)
    }
}

impl Add for Scalar {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self(add_limbs(&self.0, &rhs.0))
    }
}

impl Sub for Scalar {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        Self(sub_limbs(&self.0, &rhs.0))
    }
}

impl Neg for Scalar {
    type Output = Self;
    #[inline(always)]
    fn neg(self) -> Self {
        Self(sub_limbs(&[0; 9], &self.0))
    }
}

impl Mul for Scalar {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        Self(mont_mul(&self.0, &rhs.0))
    }
}
