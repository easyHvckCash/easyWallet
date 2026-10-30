#ifndef SECP256K1_CUH
#define SECP256K1_CUH

/**
 * secp256k1 Elliptic Curve Operations for CUDA
 * Based on 8x32-bit limbs for 256-bit field elements
 * Reference: ipsbruno3/secp256k1-gpu-accelerator, UltrafastSecp256k1
 *
 * Field: p = 2^256 - 2^32 - 977
 * Order: n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 * Generator: G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
 *                 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
 */

#include <stdint.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t  i64;

// 256-bit field element: 8 × 32-bit limbs (little-endian)
typedef struct { u32 d[8]; } fe_t;

// Jacobian point: (X, Y, Z) where affine = (X/Z^2, Y/Z^3)
typedef struct { fe_t x, y, z; } jpoint_t;

// secp256k1 field prime p
__device__ __constant__ u32 SECP256K1_P[8] = {
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

// Generator point G (affine)
__device__ __constant__ u32 SECP256K1_GX[8] = {
    0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
    0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E
};
__device__ __constant__ u32 SECP256K1_GY[8] = {
    0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
    0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77
};

// ====== Field Arithmetic (mod p) ======

__device__ __forceinline__ void fe_set(fe_t *r, const u32 *src) {
    #pragma unroll
    for (int i = 0; i < 8; i++) r->d[i] = src[i];
}

__device__ __forceinline__ void fe_zero(fe_t *r) {
    #pragma unroll
    for (int i = 0; i < 8; i++) r->d[i] = 0;
}

__device__ __forceinline__ void fe_one(fe_t *r) {
    r->d[0] = 1;
    for (int i = 1; i < 8; i++) r->d[i] = 0;
}

__device__ __forceinline__ int fe_is_zero(const fe_t *a) {
    u32 v = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) v |= a->d[i];
    return v == 0;
}

__device__ __forceinline__ void fe_copy(fe_t *r, const fe_t *a) {
    #pragma unroll
    for (int i = 0; i < 8; i++) r->d[i] = a->d[i];
}

// r = a + b mod p
__device__ void fe_add(fe_t *r, const fe_t *a, const fe_t *b) {
    u64 carry = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        carry += (u64)a->d[i] + b->d[i];
        r->d[i] = (u32)carry;
        carry >>= 32;
    }
    // Reduce if >= p: try subtracting p
    i64 borrow = 0;
    u32 tmp[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        borrow += (i64)(u64)r->d[i] - (i64)(u64)SECP256K1_P[i];
        tmp[i] = (u32)borrow;
        borrow >>= 32;
    }
    // If carry from addition or no borrow from subtraction: use tmp (reduced)
    int use_reduced = ((i64)carry + borrow) >= 0;
    #pragma unroll
    for (int i = 0; i < 8; i++)
        r->d[i] = use_reduced ? tmp[i] : r->d[i];
}

// r = a - b mod p
__device__ void fe_sub(fe_t *r, const fe_t *a, const fe_t *b) {
    i64 borrow = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        borrow = (i64)a->d[i] - b->d[i] + borrow;
        r->d[i] = (u32)borrow;
        borrow >>= 32;
    }
    // If result is negative, add p
    if (borrow < 0) {
        u64 carry = 0;
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            carry += (u64)r->d[i] + SECP256K1_P[i];
            r->d[i] = (u32)carry;
            carry >>= 32;
        }
    }
}

// r = a * b mod p (using schoolbook multiplication + fast secp256k1 reduction)
__device__ void fe_mul(fe_t *r, const fe_t *a, const fe_t *b) {
    u64 t[16] = {0};

    // Schoolbook 8x8 multiply → 512-bit product
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        u64 carry = 0;
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            u64 prod = (u64)a->d[i] * b->d[j] + t[i+j] + carry;
            t[i+j] = prod & 0xFFFFFFFF;
            carry = prod >> 32;
        }
        t[i+8] = carry;
    }

    // Fast reduction mod p = 2^256 - 0x1000003D1
    // t[0..7] = low 256 bits, t[8..15] = high 256 bits
    // result = low + high * 0x1000003D1
    u64 carry = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        carry += t[i] + t[i+8] * 0x1000003D1ULL;
        r->d[i] = (u32)carry;
        carry >>= 32;
    }
    // Handle final carry
    carry *= 0x1000003D1ULL;
    carry += r->d[0];
    r->d[0] = (u32)carry;
    carry >>= 32;
    if (carry) {
        for (int i = 1; i < 8 && carry; i++) {
            carry += r->d[i];
            r->d[i] = (u32)carry;
            carry >>= 32;
        }
    }
}

// r = a^2 mod p
__device__ void fe_sqr(fe_t *r, const fe_t *a) {
    fe_mul(r, a, a);
}

// r = a^(-1) mod p using Fermat: a^(p-2)
__device__ void fe_inv(fe_t *r, const fe_t *a) {
    // p-2 in big-endian u32 words (MSW first):
    // FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2D
    const u32 exp[8] = {
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFC2D
    };
    fe_one(r);
    for (int w = 0; w < 8; w++) {
        for (int bit = 31; bit >= 0; bit--) {
            fe_sqr(r, r);
            if ((exp[w] >> bit) & 1) {
                fe_mul(r, r, a);
            }
        }
    }
}

// ====== Point Operations (Jacobian coordinates) ======

__device__ void point_set_infinity(jpoint_t *p) {
    fe_zero(&p->x); fe_one(&p->y); fe_zero(&p->z);
}

__device__ int point_is_infinity(const jpoint_t *p) {
    return fe_is_zero(&p->z);
}

// Point doubling: R = 2*P (Jacobian)
__device__ void point_double(jpoint_t *r, const jpoint_t *p) {
    if (fe_is_zero(&p->z)) { point_set_infinity(r); return; }

    fe_t s, m, t, y2;

    // S = 4*X*Y^2
    fe_sqr(&y2, &p->y);
    fe_mul(&s, &p->x, &y2);
    fe_add(&s, &s, &s); fe_add(&s, &s, &s); // *4

    // M = 3*X^2 (a=0 for secp256k1)
    fe_sqr(&m, &p->x);
    fe_add(&t, &m, &m); fe_add(&m, &t, &m); // *3

    // X' = M^2 - 2*S
    fe_sqr(&r->x, &m);
    fe_sub(&r->x, &r->x, &s);
    fe_sub(&r->x, &r->x, &s);

    // Y' = M*(S - X') - 8*Y^4
    fe_sub(&t, &s, &r->x);
    fe_mul(&r->y, &m, &t);
    fe_sqr(&t, &y2); // Y^4
    fe_add(&t, &t, &t); fe_add(&t, &t, &t); fe_add(&t, &t, &t); // *8
    fe_sub(&r->y, &r->y, &t);

    // Z' = 2*Y*Z
    fe_mul(&r->z, &p->y, &p->z);
    fe_add(&r->z, &r->z, &r->z);
}

// Point addition: R = P + Q (Jacobian, mixed: Q.z = 1 for affine Q)
__device__ void point_add_mixed(jpoint_t *r, const jpoint_t *p, const fe_t *qx, const fe_t *qy) {
    if (fe_is_zero(&p->z)) {
        fe_copy(&r->x, qx); fe_copy(&r->y, qy); fe_one(&r->z);
        return;
    }

    fe_t z2, z3, u2, s2, h, hh, hhh, rr;

    fe_sqr(&z2, &p->z);
    fe_mul(&z3, &z2, &p->z);
    fe_mul(&u2, qx, &z2);    // U2 = qx * Z1^2
    fe_mul(&s2, qy, &z3);    // S2 = qy * Z1^3

    fe_sub(&h, &u2, &p->x);  // H = U2 - X1
    fe_sub(&rr, &s2, &p->y); // R = S2 - Y1

    fe_sqr(&hh, &h);
    fe_mul(&hhh, &hh, &h);

    fe_t v;
    fe_mul(&v, &p->x, &hh);

    // X3 = R^2 - HHH - 2*V
    fe_sqr(&r->x, &rr);
    fe_sub(&r->x, &r->x, &hhh);
    fe_sub(&r->x, &r->x, &v);
    fe_sub(&r->x, &r->x, &v);

    // Y3 = R*(V - X3) - Y1*HHH
    fe_sub(&v, &v, &r->x);
    fe_mul(&r->y, &rr, &v);
    fe_t tmp;
    fe_mul(&tmp, &p->y, &hhh);
    fe_sub(&r->y, &r->y, &tmp);

    // Z3 = Z1 * H
    fe_mul(&r->z, &p->z, &h);
}

// Scalar multiplication: R = k * G (using double-and-add)
// scalar is little-endian u32[8]: scalar[0]=LSW, scalar[7]=MSW
__device__ void point_mul_generator(jpoint_t *r, const u32 scalar[8]) {
    point_set_infinity(r);
    fe_t gx, gy;
    fe_set(&gx, SECP256K1_GX);
    fe_set(&gy, SECP256K1_GY);

    // Scan bits from MSB to LSB (scalar[7] bit 31 is MSB)
    for (int w = 7; w >= 0; w--) {
        for (int bit = 31; bit >= 0; bit--) {
            jpoint_t tmp;
            point_double(&tmp, r);
            fe_copy(&r->x, &tmp.x);
            fe_copy(&r->y, &tmp.y);
            fe_copy(&r->z, &tmp.z);

            if ((scalar[w] >> bit) & 1) {
                point_add_mixed(&tmp, r, &gx, &gy);
                fe_copy(&r->x, &tmp.x);
                fe_copy(&r->y, &tmp.y);
                fe_copy(&r->z, &tmp.z);
            }
        }
    }
}

// Scalar multiplication with arbitrary base point
// scalar is little-endian u32[8]: scalar[0]=LSW, scalar[7]=MSW
__device__ void point_mul(jpoint_t *r, const u32 scalar[8], const fe_t *px, const fe_t *py) {
    point_set_infinity(r);

    for (int w = 7; w >= 0; w--) {
        for (int bit = 31; bit >= 0; bit--) {
            jpoint_t tmp;
            point_double(&tmp, r);
            fe_copy(&r->x, &tmp.x);
            fe_copy(&r->y, &tmp.y);
            fe_copy(&r->z, &tmp.z);

            if ((scalar[w] >> bit) & 1) {
                point_add_mixed(&tmp, r, px, py);
                fe_copy(&r->x, &tmp.x);
                fe_copy(&r->y, &tmp.y);
                fe_copy(&r->z, &tmp.z);
            }
        }
    }
}

// Convert Jacobian → Affine (compressed pubkey: 33 bytes)
__device__ void point_to_compressed(const jpoint_t *p, uint8_t pubkey[33]) {
    fe_t z_inv, z2, z3, ax, ay;

    fe_inv(&z_inv, &p->z);
    fe_sqr(&z2, &z_inv);
    fe_mul(&z3, &z2, &z_inv);
    fe_mul(&ax, &p->x, &z2);
    fe_mul(&ay, &p->y, &z3);

    // Prefix: 0x02 if y is even, 0x03 if odd
    pubkey[0] = (ay.d[0] & 1) ? 0x03 : 0x02;

    // X coordinate in big-endian
    for (int i = 7; i >= 0; i--) {
        int off = 1 + (7 - i) * 4;
        pubkey[off + 0] = (ax.d[i] >> 24) & 0xFF;
        pubkey[off + 1] = (ax.d[i] >> 16) & 0xFF;
        pubkey[off + 2] = (ax.d[i] >> 8) & 0xFF;
        pubkey[off + 3] = ax.d[i] & 0xFF;
    }
}

#endif // SECP256K1_CUH
