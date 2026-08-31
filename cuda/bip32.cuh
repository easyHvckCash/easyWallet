#ifndef BIP32_CUH
#define BIP32_CUH

/**
 * BIP32 HD Key Derivation on GPU
 * master_key → child_key → pubkey → hash160
 */

#include "secp256k1.cuh"
#include "hash160.cuh"

// HMAC-SHA512 (reuse from scanner.cu sha512 impl, simplified for BIP32 key derivation)
// BIP32 uses HMAC-SHA512 with key="Bitcoin seed" for master key,
// and with chain_code as key for child key derivation.

// Minimal SHA-512 for HMAC in BIP32 context
// (reuse the sha512 implementation from the main kernel)

__device__ __constant__ u64 SHA512_K_BIP[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

#define BIP_ROTR64(x, n) (((x) >> (n)) | ((x) << (64-(n))))
#define BIP_CH64(x,y,z) (((x)&(y))^((~(x))&(z)))
#define BIP_MAJ64(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define BIP_EP0_64(x) (BIP_ROTR64(x,28)^BIP_ROTR64(x,34)^BIP_ROTR64(x,39))
#define BIP_EP1_64(x) (BIP_ROTR64(x,14)^BIP_ROTR64(x,18)^BIP_ROTR64(x,41))
#define BIP_SIG0_64(x) (BIP_ROTR64(x,1)^BIP_ROTR64(x,8)^((x)>>7))
#define BIP_SIG1_64(x) (BIP_ROTR64(x,19)^BIP_ROTR64(x,61)^((x)>>6))

__device__ void bip_sha512_transform(u64 state[8], const uint8_t block[128]) {
    u64 w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = 0;
        for (int j = 0; j < 8; j++)
            w[i] |= ((u64)block[i*8+j]) << (56 - j*8);
    }
    for (int i = 16; i < 80; i++)
        w[i] = BIP_SIG1_64(w[i-2]) + w[i-7] + BIP_SIG0_64(w[i-15]) + w[i-16];

    u64 a=state[0],b=state[1],c=state[2],d=state[3];
    u64 e=state[4],f=state[5],g=state[6],h=state[7];

    for (int i = 0; i < 80; i++) {
        u64 t1 = h + BIP_EP1_64(e) + BIP_CH64(e,f,g) + SHA512_K_BIP[i] + w[i];
        u64 t2 = BIP_EP0_64(a) + BIP_MAJ64(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;
    state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}

__device__ void bip_sha512(const uint8_t *data, u32 len, uint8_t hash[64]) {
    u64 state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    u32 blocks = len / 128;
    for (u32 i = 0; i < blocks; i++)
        bip_sha512_transform(state, data + i*128);

    uint8_t pad[256] = {0};
    u32 rem = len % 128;
    for (u32 i = 0; i < rem; i++) pad[i] = data[blocks*128 + i];
    pad[rem] = 0x80;
    u32 pad_blocks = (rem < 112) ? 1 : 2;
    u64 bits = (u64)len * 8;
    uint8_t *last = pad + (pad_blocks-1)*128;
    last[120]=(bits>>56); last[121]=(bits>>48); last[122]=(bits>>40); last[123]=(bits>>32);
    last[124]=(bits>>24); last[125]=(bits>>16); last[126]=(bits>>8); last[127]=bits;
    for (u32 i = 0; i < pad_blocks; i++)
        bip_sha512_transform(state, pad + i*128);

    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            hash[i*8+j] = (state[i] >> (56-j*8)) & 0xFF;
}

__device__ void bip_hmac_sha512(const uint8_t *key, u32 klen, const uint8_t *msg, u32 mlen, uint8_t out[64]) {
    uint8_t k_pad[128] = {0};
    if (klen > 128) {
        bip_sha512(key, klen, k_pad); // hash key if > block size
    } else {
        for (u32 i = 0; i < klen; i++) k_pad[i] = key[i];
    }

    uint8_t ipad_data[256];
    for (int i = 0; i < 128; i++) ipad_data[i] = k_pad[i] ^ 0x36;
    for (u32 i = 0; i < mlen; i++) ipad_data[128+i] = msg[i];
    uint8_t inner[64];
    bip_sha512(ipad_data, 128+mlen, inner);

    uint8_t opad_data[192];
    for (int i = 0; i < 128; i++) opad_data[i] = k_pad[i] ^ 0x5C;
    for (int i = 0; i < 64; i++) opad_data[128+i] = inner[i];
    bip_sha512(opad_data, 192, out);
}

// BIP32 master key from seed
__device__ void bip32_master_key(const uint8_t seed[64], uint8_t secret[32], uint8_t chain_code[32]) {
    const uint8_t bip32_key[] = "Bitcoin seed"; // 12 bytes
    uint8_t I[64];
    bip_hmac_sha512(bip32_key, 12, seed, 64, I);
    for (int i = 0; i < 32; i++) secret[i] = I[i];
    for (int i = 0; i < 32; i++) chain_code[i] = I[32+i];
}

// Parse 32 bytes as big-endian u32[8] (for secp256k1 scalar)
__device__ void bytes_to_scalar(const uint8_t bytes[32], u32 scalar[8]) {
    for (int i = 0; i < 8; i++) {
        scalar[7-i] = ((u32)bytes[i*4]<<24) | ((u32)bytes[i*4+1]<<16) |
                      ((u32)bytes[i*4+2]<<8) | bytes[i*4+3];
    }
}

// BIP32 normal child derivation (non-hardened) from parent pubkey + chain
__device__ void bip32_ckd_pub(
    const uint8_t parent_pubkey[33], const uint8_t parent_chain[32],
    u32 index,
    uint8_t child_pubkey[33], uint8_t child_chain[32]
) {
    // Data = 0x00 || ser256(parent_key) || ser32(index)  [hardened]
    // Data = serP(parent_pubkey) || ser32(index)         [normal]
    uint8_t data[37];
    for (int i = 0; i < 33; i++) data[i] = parent_pubkey[i];
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;

    uint8_t I[64];
    bip_hmac_sha512(parent_chain, 32, data, 37, I);

    // child_key = parse256(IL) + parent_key (mod n)
    // For public derivation: child_point = parse256(IL)*G + parent_point
    u32 il_scalar[8];
    bytes_to_scalar(I, il_scalar);

    // Compute IL*G
    jpoint_t il_point;
    point_mul_generator(&il_point, il_scalar);

    // Decompress parent pubkey
    // For simplicity in GPU derivation: we derive from private keys (hardened first levels)
    // Then use public for the last index level
    // Store child chain code
    for (int i = 0; i < 32; i++) child_chain[i] = I[32+i];

    // Get compressed pubkey of il_point
    point_to_compressed(&il_point, child_pubkey);
}

// BIP32 private child derivation (hardened)
__device__ void bip32_ckd_priv(
    const uint8_t parent_secret[32], const uint8_t parent_chain[32],
    u32 index,
    uint8_t child_secret[32], uint8_t child_chain[32]
) {
    uint8_t data[37];
    if (index >= 0x80000000) {
        // Hardened: data = 0x00 || parent_secret || index
        data[0] = 0x00;
        for (int i = 0; i < 32; i++) data[1+i] = parent_secret[i];
    } else {
        // Normal: data = serP(parent_pubkey) || index
        u32 scalar[8];
        bytes_to_scalar(parent_secret, scalar);
        jpoint_t pub_point;
        point_mul_generator(&pub_point, scalar);
        point_to_compressed(&pub_point, data);
    }
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;

    uint8_t I[64];
    bip_hmac_sha512(parent_chain, 32, data, 37, I);

    // child_secret = (parse256(IL) + parent_secret) mod n
    u32 il[8], ps[8];
    bytes_to_scalar(I, il);
    bytes_to_scalar(parent_secret, ps);

    // Add il + ps as 256-bit integers
    u64 carry = 0;
    u32 sum[8];
    for (int i = 0; i < 8; i++) {
        carry += (u64)il[i] + (u64)ps[i];
        sum[i] = (u32)carry;
        carry >>= 32;
    }

    // secp256k1 order n
    const u32 ORDER[8] = {
        0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
        0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    // Reduce mod n: if sum >= ORDER, subtract ORDER
    i64 borrow = 0;
    u32 reduced[8];
    for (int i = 0; i < 8; i++) {
        borrow += (i64)(u64)sum[i] - (i64)(u64)ORDER[i];
        reduced[i] = (u32)borrow;
        borrow >>= 32;
    }
    // carry from addition + borrow from subtraction determines which to use
    // If (carry + borrow) >= 0, then sum >= ORDER, use reduced
    int use_reduced = ((i64)carry + borrow) >= 0;

    u32 *result = use_reduced ? reduced : sum;

    // Convert result (little-endian u32[8]) back to big-endian bytes
    for (int i = 0; i < 8; i++) {
        u32 val = result[7 - i]; // result[7] is MSW
        child_secret[i*4 + 0] = (val >> 24) & 0xFF;
        child_secret[i*4 + 1] = (val >> 16) & 0xFF;
        child_secret[i*4 + 2] = (val >> 8) & 0xFF;
        child_secret[i*4 + 3] = val & 0xFF;
    }

    for (int i = 0; i < 32; i++) child_chain[i] = I[32+i];
}

// Full BIP32 derivation path on GPU
// path: array of u32 indices (with 0x80000000 bit for hardened)
// path_len: number of levels
__device__ void bip32_derive_path(
    const uint8_t master_secret[32], const uint8_t master_chain[32],
    const u32 *path, u32 path_len,
    uint8_t final_secret[32], uint8_t final_chain[32]
) {
    uint8_t cur_secret[32], cur_chain[32];
    for (int i = 0; i < 32; i++) { cur_secret[i] = master_secret[i]; cur_chain[i] = master_chain[i]; }

    for (u32 level = 0; level < path_len; level++) {
        uint8_t next_secret[32], next_chain[32];
        bip32_ckd_priv(cur_secret, cur_chain, path[level], next_secret, next_chain);
        for (int i = 0; i < 32; i++) { cur_secret[i] = next_secret[i]; cur_chain[i] = next_chain[i]; }
    }

    for (int i = 0; i < 32; i++) { final_secret[i] = cur_secret[i]; final_chain[i] = cur_chain[i]; }
}

// Derive pubkey from private key → compressed 33 bytes
__device__ void privkey_to_pubkey(const uint8_t secret[32], uint8_t pubkey[33]) {
    u32 scalar[8];
    bytes_to_scalar(secret, scalar);
    jpoint_t point;
    point_mul_generator(&point, scalar);
    point_to_compressed(&point, pubkey);
}

// Derive hash160 from private key (the address matching fingerprint)
__device__ void privkey_to_hash160(const uint8_t secret[32], uint8_t h160[20]) {
    uint8_t pubkey[33];
    privkey_to_pubkey(secret, pubkey);
    hash160(pubkey, 33, h160);
}

#endif // BIP32_CUH
