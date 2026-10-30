/**
 * scanner.cu — Full GPU Pipeline
 * PBKDF2-HMAC-SHA512 → BIP32 derivation → secp256k1 → hash160 → BinaryFuse8 match
 *
 * P0: secp256k1 on GPU
 * P1: Double-buffered streams (managed from Rust side)
 * P3: BinaryFuse8 on GPU
 * P4: Optimized SHA-512 (unrolled, midstate pre-computation)
 *
 * Compilation:
 *   nvcc -O3 -arch=sm_75 -o scanner.ptx --ptx scanner.cu
 */

#include <stdint.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t  i64;

#include "secp256k1.cuh"
#include "hash160.cuh"
#include "bip32.cuh"

// ========== BinaryFuse8 GPU Filter ==========
// Replicates xorf's BinaryFuse8 contains() logic on GPU
// Algorithm: https://github.com/FastFilter/xorfilter

struct GpuBinaryFuse8 {
    u32 segment_length;
    u32 segment_count_length;
    u32 segment_length_mask;
    u32 array_length;
    u64 seed;
    const uint8_t *fingerprints; // device pointer
};

// xorf's mix() function (equivalent to splitmix64-based hash)
__device__ u64 fuse_mix(u64 key, u64 seed) {
    key += seed;
    key ^= key >> 33;
    key *= 0xff51afd7ed558ccdULL;
    key ^= key >> 33;
    key *= 0xc4ceb9fe1a85ec53ULL;
    key ^= key >> 33;
    return key;
}

// xorf's fingerprint macro: top bits of hash
__device__ uint8_t fuse_fingerprint(u64 hash) {
    return (uint8_t)(hash ^ (hash >> 32));
}

// xorf's hash_of_hash: compute 3 indices from hash
__device__ void fuse_hash_of_hash(u64 hash, u32 seg_len, u32 seg_mask, u32 seg_count_len,
                                   u32 *h0, u32 *h1, u32 *h2) {
    // hi = (hash * segment_count_length) >> 64
    u64 hi = __umul64hi(hash, (u64)seg_count_len);
    *h0 = (u32)hi;
    *h1 = *h0 + seg_len;
    *h2 = *h1 + seg_len;
    *h1 ^= ((u32)(hash >> 18)) & seg_mask;
    *h2 ^= ((u32)hash) & seg_mask;
}

__device__ bool fuse8_contains(const GpuBinaryFuse8 *filter, u64 key) {
    u64 hash = fuse_mix(key, filter->seed);
    uint8_t f = fuse_fingerprint(hash);

    u32 h0, h1, h2;
    fuse_hash_of_hash(hash, filter->segment_length, filter->segment_length_mask,
                      filter->segment_count_length, &h0, &h1, &h2);

    f ^= filter->fingerprints[h0] ^ filter->fingerprints[h1] ^ filter->fingerprints[h2];
    return f == 0;
}

// ========== Optimized PBKDF2-HMAC-SHA512 ==========
// (P4: Using optimized SHA-512 with midstate pre-computation)

__device__ __constant__ u64 K512[80] = {
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

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64-(n))))
#define CH64(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ64(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0_64(x) (ROTR64(x,28)^ROTR64(x,34)^ROTR64(x,39))
#define EP1_64(x) (ROTR64(x,14)^ROTR64(x,18)^ROTR64(x,41))
#define SIG0_64(x) (ROTR64(x,1)^ROTR64(x,8)^((x)>>7))
#define SIG1_64(x) (ROTR64(x,19)^ROTR64(x,61)^((x)>>6))

__device__ void sha512_compress(u64 state[8], const u64 w[16]) {
    u64 W[80];
    #pragma unroll
    for (int i = 0; i < 16; i++) W[i] = w[i];
    #pragma unroll
    for (int i = 16; i < 80; i++)
        W[i] = SIG1_64(W[i-2]) + W[i-7] + SIG0_64(W[i-15]) + W[i-16];

    u64 a=state[0],b=state[1],c=state[2],d=state[3];
    u64 e=state[4],f=state[5],g=state[6],h=state[7];

    #pragma unroll
    for (int i = 0; i < 80; i++) {
        u64 t1 = h + EP1_64(e) + CH64(e,f,g) + K512[i] + W[i];
        u64 t2 = EP0_64(a) + MAJ64(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;
    state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}

// SHA-512 with pre-computed IPAD/OPAD midstates
__device__ void sha512_with_midstate(const u64 midstate[8], const uint8_t *msg, u32 msg_len, u32 prefix_len, uint8_t hash[64]) {
    u64 state[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) state[i] = midstate[i];

    // Process remaining full blocks
    u32 total_len = prefix_len + msg_len;
    u32 processed = prefix_len; // midstate already includes the prefix (ipad/opad block)
    u32 pos = 0;

    while (pos + 128 <= msg_len) {
        u64 w[16];
        for (int i = 0; i < 16; i++) {
            w[i] = 0;
            for (int j = 0; j < 8; j++)
                w[i] |= ((u64)msg[pos + i*8 + j]) << (56 - j*8);
        }
        sha512_compress(state, w);
        pos += 128;
    }

    // Final block with padding
    uint8_t pad[256] = {0};
    u32 rem = msg_len - pos;
    for (u32 i = 0; i < rem; i++) pad[i] = msg[pos + i];
    pad[rem] = 0x80;

    u32 pad_blocks = (rem < 112) ? 1 : 2;
    u64 total_bits = (u64)total_len * 8;
    uint8_t *last = pad + (pad_blocks - 1) * 128;
    last[120] = (total_bits >> 56); last[121] = (total_bits >> 48);
    last[122] = (total_bits >> 40); last[123] = (total_bits >> 32);
    last[124] = (total_bits >> 24); last[125] = (total_bits >> 16);
    last[126] = (total_bits >> 8);  last[127] = total_bits;

    for (u32 i = 0; i < pad_blocks; i++) {
        u64 w[16];
        for (int j = 0; j < 16; j++) {
            w[j] = 0;
            for (int k = 0; k < 8; k++)
                w[j] |= ((u64)pad[i*128 + j*8 + k]) << (56 - k*8);
        }
        sha512_compress(state, w);
    }

    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            hash[i*8+j] = (state[i] >> (56 - j*8)) & 0xFF;
}

// HMAC-SHA512 with midstate optimization
__device__ void hmac_sha512_midstate(const u64 ipad_mid[8], const u64 opad_mid[8],
                                     const uint8_t *msg, u32 mlen, uint8_t out[64]) {
    // Inner hash: ipad_midstate + msg
    uint8_t inner[64];
    sha512_with_midstate(ipad_mid, msg, mlen, 128, inner);

    // Outer hash: opad_midstate + inner_hash
    sha512_with_midstate(opad_mid, inner, 64, 128, out);
}

// Compute IPAD/OPAD midstates for a given key (mnemonic as password for PBKDF2)
__device__ void compute_hmac_midstates(const uint8_t *key, u32 klen, u64 ipad_mid[8], u64 opad_mid[8]) {
    uint8_t k_pad[128] = {0};
    if (klen > 128) {
        // SHA-512 the key first
        u64 ks[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };
        // Process key through SHA-512 (simplified for typical mnemonic lengths < 128)
        uint8_t pad_blk[256] = {0};
        for (u32 i = 0; i < klen; i++) pad_blk[i] = key[i];
        pad_blk[klen] = 0x80;
        u32 pb = (klen < 112) ? 1 : 2;
        u64 bits = (u64)klen * 8;
        uint8_t *lst = pad_blk + (pb-1)*128;
        lst[120]=(bits>>56); lst[121]=(bits>>48); lst[122]=(bits>>40); lst[123]=(bits>>32);
        lst[124]=(bits>>24); lst[125]=(bits>>16); lst[126]=(bits>>8); lst[127]=bits;
        for (u32 i = 0; i < pb; i++) {
            u64 w[16];
            for (int j = 0; j < 16; j++) { w[j] = 0; for (int k=0;k<8;k++) w[j]|=((u64)pad_blk[i*128+j*8+k])<<(56-k*8); }
            sha512_compress(ks, w);
        }
        for (int i = 0; i < 8; i++) for (int j=0;j<8;j++) k_pad[i*8+j]=(ks[i]>>(56-j*8))&0xFF;
    } else {
        for (u32 i = 0; i < klen; i++) k_pad[i] = key[i];
    }

    // Build IPAD block and compute midstate
    u64 ipad_block[16], opad_block[16];
    for (int i = 0; i < 16; i++) {
        u64 val = 0;
        for (int j = 0; j < 8; j++) val |= ((u64)(k_pad[i*8+j] ^ 0x36)) << (56-j*8);
        ipad_block[i] = val;
    }
    for (int i = 0; i < 16; i++) {
        u64 val = 0;
        for (int j = 0; j < 8; j++) val |= ((u64)(k_pad[i*8+j] ^ 0x5C)) << (56-j*8);
        opad_block[i] = val;
    }

    // IPAD midstate
    ipad_mid[0]=0x6a09e667f3bcc908ULL; ipad_mid[1]=0xbb67ae8584caa73bULL;
    ipad_mid[2]=0x3c6ef372fe94f82bULL; ipad_mid[3]=0xa54ff53a5f1d36f1ULL;
    ipad_mid[4]=0x510e527fade682d1ULL; ipad_mid[5]=0x9b05688c2b3e6c1fULL;
    ipad_mid[6]=0x1f83d9abfb41bd6bULL; ipad_mid[7]=0x5be0cd19137e2179ULL;
    sha512_compress(ipad_mid, ipad_block);

    // OPAD midstate
    opad_mid[0]=0x6a09e667f3bcc908ULL; opad_mid[1]=0xbb67ae8584caa73bULL;
    opad_mid[2]=0x3c6ef372fe94f82bULL; opad_mid[3]=0xa54ff53a5f1d36f1ULL;
    opad_mid[4]=0x510e527fade682d1ULL; opad_mid[5]=0x9b05688c2b3e6c1fULL;
    opad_mid[6]=0x1f83d9abfb41bd6bULL; opad_mid[7]=0x5be0cd19137e2179ULL;
    sha512_compress(opad_mid, opad_block);
}

// PBKDF2-HMAC-SHA512 with midstate optimization (2048 iterations, dkLen=64)
__device__ void pbkdf2_hmac_sha512_opt(const uint8_t *password, u32 pass_len,
                                       const uint8_t *salt, u32 salt_len,
                                       uint8_t dk[64]) {
    // Pre-compute HMAC midstates for password
    u64 ipad_mid[8], opad_mid[8];
    compute_hmac_midstates(password, pass_len, ipad_mid, opad_mid);

    // PBKDF2 block 1: salt || INT(1)
    uint8_t salt_block[128]; // salt + 4 bytes for block index
    for (u32 i = 0; i < salt_len; i++) salt_block[i] = salt[i];
    salt_block[salt_len] = 0; salt_block[salt_len+1] = 0;
    salt_block[salt_len+2] = 0; salt_block[salt_len+3] = 1;

    uint8_t U[64], T[64];
    hmac_sha512_midstate(ipad_mid, opad_mid, salt_block, salt_len + 4, U);
    for (int i = 0; i < 64; i++) T[i] = U[i];

    // Iterations 2..2048
    for (int iter = 1; iter < 2048; iter++) {
        uint8_t U_next[64];
        hmac_sha512_midstate(ipad_mid, opad_mid, U, 64, U_next);
        for (int i = 0; i < 64; i++) { U[i] = U_next[i]; T[i] ^= U_next[i]; }
    }

    for (int i = 0; i < 64; i++) dk[i] = T[i];
}

// ========== Full Pipeline Kernel ==========

// BIP44/49/84 derivation paths (hardened levels + external chain)
// m/44'/0'/0'/0/index  → P2PKH
// m/49'/0'/0'/0/index  → P2SH-P2WPKH
// m/84'/0'/0'/0/index  → P2WPKH
#define NUM_PATHS 3
#define H(x) ((x) | 0x80000000u)

__device__ __constant__ u32 DERIV_PATHS[NUM_PATHS][4] = {
    { H(44), H(0), H(0), 0 },  // BIP44
    { H(49), H(0), H(0), 0 },  // BIP49
    { H(84), H(0), H(0), 0 },  // BIP84
};

// Main kernel: full pipeline per mnemonic
// Each thread processes one mnemonic through the full pipeline
// Outputs: hit flags and hash160 results for matching
extern "C" __global__ void scan_full_pipeline(
    const uint8_t *mnemonics,       // packed mnemonics (stride = max_mnemonic_len)
    const u32 *mnemonic_lens,       // actual length of each mnemonic
    u32 count,                      // number of mnemonics
    u32 max_mnemonic_len,           // stride
    u32 depth,                      // index depth (number of addresses per path)
    // BinaryFuse8 filter on GPU
    u32 fuse_segment_length,
    u32 fuse_segment_count_length,
    u32 fuse_segment_length_mask,
    u32 fuse_array_length,
    u64 fuse_seed,
    const uint8_t *fuse_fingerprints, // device pointer to filter data
    // Outputs
    u32 *hit_flags,                 // 1 if any address matched, 0 otherwise (per mnemonic)
    uint8_t *hit_hash160s           // 20 bytes per hit for verification (NUM_PATHS * depth * 20 per mnemonic)
) {
    u32 idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    const uint8_t *mnemonic = mnemonics + (u64)idx * max_mnemonic_len;
    u32 mlen = mnemonic_lens[idx];

    // Step 1: PBKDF2-HMAC-SHA512 (mnemonic → 64-byte seed)
    // Salt = "mnemonic" (8 bytes, no passphrase)
    const uint8_t salt[] = {'m','n','e','m','o','n','i','c'};
    uint8_t seed[64];
    pbkdf2_hmac_sha512_opt(mnemonic, mlen, salt, 8, seed);

    // Step 2: BIP32 master key
    uint8_t master_secret[32], master_chain[32];
    bip32_master_key(seed, master_secret, master_chain);

    // Step 3: For each path × depth, derive address and check filter
    GpuBinaryFuse8 filter;
    filter.segment_length = fuse_segment_length;
    filter.segment_count_length = fuse_segment_count_length;
    filter.segment_length_mask = fuse_segment_length_mask;
    filter.array_length = fuse_array_length;
    filter.seed = fuse_seed;
    filter.fingerprints = fuse_fingerprints;

    u32 hit = 0;

    for (u32 p = 0; p < NUM_PATHS; p++) {
        // Derive to m/purpose'/0'/0'/0
        uint8_t cur_secret[32], cur_chain[32];
        for (int i = 0; i < 32; i++) { cur_secret[i] = master_secret[i]; cur_chain[i] = master_chain[i]; }

        for (u32 level = 0; level < 4; level++) {
            uint8_t next_s[32], next_c[32];
            bip32_ckd_priv(cur_secret, cur_chain, DERIV_PATHS[p][level], next_s, next_c);
            for (int i = 0; i < 32; i++) { cur_secret[i] = next_s[i]; cur_chain[i] = next_c[i]; }
        }

        // Derive index 0..depth-1
        for (u32 child = 0; child < depth; child++) {
            uint8_t child_secret[32], child_chain[32];
            bip32_ckd_priv(cur_secret, cur_chain, child, child_secret, child_chain);

            // Private key → pubkey → hash160
            uint8_t h160[20];
            privkey_to_hash160(child_secret, h160);

            // Always store hash160 to output buffer for host-side address encoding
            u32 slot = p * depth + child;
            uint8_t *out = hit_hash160s + (u64)idx * NUM_PATHS * depth * 20 + slot * 20;
            for (int i = 0; i < 20; i++) out[i] = h160[i];

            // Convert hash160 to u64 key for filter lookup
            u64 key = 0;
            for (int i = 0; i < 8; i++) key |= ((u64)h160[i]) << (i*8);

            if (fuse8_contains(&filter, key)) {
                hit = 1;
            }
        }
    }

    hit_flags[idx] = hit;
}

// ========== Legacy kernel (PBKDF2 only, for fallback) ==========
extern "C" __global__ void pbkdf2_batch(
    const uint8_t *mnemonics,
    const u32 *mnemonic_lens,
    u32 count,
    u32 max_mnemonic_len,
    uint8_t *seeds_out
) {
    u32 idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    const uint8_t *mnemonic = mnemonics + (u64)idx * max_mnemonic_len;
    u32 mlen = mnemonic_lens[idx];
    const uint8_t salt[] = {'m','n','e','m','o','n','i','c'};

    uint8_t seed[64];
    pbkdf2_hmac_sha512_opt(mnemonic, mlen, salt, 8, seed);

    uint8_t *out = seeds_out + (u64)idx * 64;
    for (int i = 0; i < 64; i++) out[i] = seed[i];
}
