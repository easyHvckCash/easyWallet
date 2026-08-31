#ifndef HASH160_CUH
#define HASH160_CUH

/**
 * hash160 = RIPEMD160(SHA256(data))
 * GPU implementation for Bitcoin address generation
 */

#include <stdint.h>
typedef uint32_t u32;
typedef uint64_t u64;

// ====== SHA-256 ======

__device__ __constant__ u32 SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define SHA256_ROTR(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#define SHA256_CH(x,y,z)  (((x)&(y))^((~(x))&(z)))
#define SHA256_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SHA256_EP0(x) (SHA256_ROTR(x,2)^SHA256_ROTR(x,13)^SHA256_ROTR(x,22))
#define SHA256_EP1(x) (SHA256_ROTR(x,6)^SHA256_ROTR(x,11)^SHA256_ROTR(x,25))
#define SHA256_SIG0(x) (SHA256_ROTR(x,7)^SHA256_ROTR(x,18)^((x)>>3))
#define SHA256_SIG1(x) (SHA256_ROTR(x,17)^SHA256_ROTR(x,19)^((x)>>10))

__device__ void sha256_transform(u32 state[8], const uint8_t block[64]) {
    u32 w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((u32)block[i*4]<<24) | ((u32)block[i*4+1]<<16) |
               ((u32)block[i*4+2]<<8) | block[i*4+3];
    for (int i = 16; i < 64; i++)
        w[i] = SHA256_SIG1(w[i-2]) + w[i-7] + SHA256_SIG0(w[i-15]) + w[i-16];

    u32 a=state[0],b=state[1],c=state[2],d=state[3];
    u32 e=state[4],f=state[5],g=state[6],h=state[7];

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        u32 t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + SHA256_K[i] + w[i];
        u32 t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

__device__ void sha256(const uint8_t *data, u32 len, uint8_t hash[32]) {
    u32 state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    u32 blocks = len / 64;
    for (u32 i = 0; i < blocks; i++)
        sha256_transform(state, data + i*64);

    uint8_t pad[128] = {0};
    u32 rem = len % 64;
    for (u32 i = 0; i < rem; i++) pad[i] = data[blocks*64 + i];
    pad[rem] = 0x80;
    u32 pad_blocks = (rem < 56) ? 1 : 2;
    u64 bits = (u64)len * 8;
    uint8_t *last = pad + (pad_blocks-1)*64;
    last[56] = bits >> 56; last[57] = bits >> 48;
    last[58] = bits >> 40; last[59] = bits >> 32;
    last[60] = bits >> 24; last[61] = bits >> 16;
    last[62] = bits >> 8;  last[63] = bits;
    for (u32 i = 0; i < pad_blocks; i++)
        sha256_transform(state, pad + i*64);

    for (int i = 0; i < 8; i++) {
        hash[i*4]   = state[i] >> 24;
        hash[i*4+1] = state[i] >> 16;
        hash[i*4+2] = state[i] >> 8;
        hash[i*4+3] = state[i];
    }
}

// ====== RIPEMD-160 ======

__device__ __constant__ u32 RMD_KL[5] = {0x00000000,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E};
__device__ __constant__ u32 RMD_KR[5] = {0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0x00000000};

__device__ __constant__ uint8_t RMD_RL[80] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
};
__device__ __constant__ uint8_t RMD_RR[80] = {
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
};
__device__ __constant__ uint8_t RMD_SL[80] = {
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
};
__device__ __constant__ uint8_t RMD_SR[80] = {
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
};

#define RMD_ROTL(x, n) (((x) << (n)) | ((x) >> (32-(n))))

__device__ u32 rmd_f(int j, u32 x, u32 y, u32 z) {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

__device__ void ripemd160(const uint8_t *data, u32 len, uint8_t hash[20]) {
    u32 h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0;

    uint8_t pad[128] = {0};
    for (u32 i = 0; i < len; i++) pad[i] = data[i];
    pad[len] = 0x80;
    u32 pad_len = (len < 56) ? 64 : 128;
    u64 bits = (u64)len * 8;
    pad[pad_len-8] = bits; pad[pad_len-7] = bits>>8;
    pad[pad_len-6] = bits>>16; pad[pad_len-5] = bits>>24;
    pad[pad_len-4] = bits>>32; pad[pad_len-3] = bits>>40;
    pad[pad_len-2] = bits>>48; pad[pad_len-1] = bits>>56;

    for (u32 blk = 0; blk < pad_len; blk += 64) {
        u32 w[16];
        for (int i = 0; i < 16; i++)
            w[i] = (u32)pad[blk+i*4] | ((u32)pad[blk+i*4+1]<<8) |
                   ((u32)pad[blk+i*4+2]<<16) | ((u32)pad[blk+i*4+3]<<24);

        u32 al=h0,bl=h1,cl=h2,dl=h3,el=h4;
        u32 ar=h0,br=h1,cr=h2,dr=h3,er=h4;

        for (int j = 0; j < 80; j++) {
            u32 tl = al + rmd_f(j, bl, cl, dl) + w[RMD_RL[j]] + RMD_KL[j/16];
            tl = RMD_ROTL(tl, RMD_SL[j]) + el;
            al=el; el=dl; dl=RMD_ROTL(cl,10); cl=bl; bl=tl;

            u32 tr = ar + rmd_f(79-j, br, cr, dr) + w[RMD_RR[j]] + RMD_KR[j/16];
            tr = RMD_ROTL(tr, RMD_SR[j]) + er;
            ar=er; er=dr; dr=RMD_ROTL(cr,10); cr=br; br=tr;
        }
        u32 t = h1 + cl + dr;
        h1 = h2 + dl + er; h2 = h3 + el + ar;
        h3 = h4 + al + br; h4 = h0 + bl + cr; h0 = t;
    }

    // Output little-endian
    for (int i = 0; i < 4; i++) {
        hash[i]    = (h0>>(8*i))&0xFF;
        hash[4+i]  = (h1>>(8*i))&0xFF;
        hash[8+i]  = (h2>>(8*i))&0xFF;
        hash[12+i] = (h3>>(8*i))&0xFF;
        hash[16+i] = (h4>>(8*i))&0xFF;
    }
}

// hash160 = RIPEMD160(SHA256(data))
__device__ void hash160(const uint8_t *data, u32 len, uint8_t out[20]) {
    uint8_t sha[32];
    sha256(data, len, sha);
    ripemd160(sha, 32, out);
}

#endif // HASH160_CUH
