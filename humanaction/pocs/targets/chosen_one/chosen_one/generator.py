"""
Chosen One (天选之子) — True random mnemonic generator over the full 2^256 key space.

Uses os.urandom() (kernel CSPRNG) to generate 256-bit entropy, then derives
a 24-word BIP-39 mnemonic. This is equivalent to rolling a fair die across
the entire Bitcoin private key space — no shortcuts, no weak seeds, no patterns.

Since the space is 2^256 ≈ 1.16×10^77, exhaustive enumeration is impossible.
This generator produces random samples indefinitely at maximum speed.
"""
import os
import sys
import hashlib
from typing import Iterator, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "coldcard", "dice_no_floor", "ngu"))
from bip39 import wordlist_en as BIP39_WORDLIST

from base import PocGenerator


def entropy_to_mnemonic_24(entropy: bytes) -> str:
    """Convert 32 bytes (256-bit) entropy to 24-word BIP-39 mnemonic.

    BIP-39 spec: entropy(256 bit) + checksum(8 bit) = 264 bit -> 24 words * 11 bit
    """
    assert len(entropy) == 32
    checksum = hashlib.sha256(entropy).digest()[0]  # first byte = 8 bits
    # Combine: 256 bits of entropy + 8 bits of checksum = 264 bits total
    combined = (int.from_bytes(entropy, 'big') << 8) | checksum
    words = []
    for i in range(24):
        shift = (23 - i) * 11
        idx = (combined >> shift) & 0x7FF
        words.append(BIP39_WORDLIST[idx])
    return ' '.join(words)


class ChosenOneGenerator(PocGenerator):
    """
    True random sampling over the full 2^256 BIP-39 mnemonic space.

    Uses os.urandom() — backed by the kernel CSPRNG (/dev/urandom on Linux,
    BCryptGenRandom on Windows). Each 32-byte draw is an independent,
    uniformly distributed sample from [0, 2^256).

    No deterministic index, no progress tracking, no resumability.
    Every run produces fresh, unpredictable mnemonics.
    """

    @property
    def poc_id(self) -> str:
        return "chosen_one"

    @property
    def poc_name(self) -> str:
        return "Chosen One (Full 2^256 random sampling)"

    @property
    def total_space(self) -> int:
        return 2 ** 256

    @property
    def batch_size(self) -> int:
        return 10000

    def generate(self, start_index: int) -> Iterator[Tuple[int, Optional[str]]]:
        """
        Yield (index, mnemonic) indefinitely.
        Each mnemonic is derived from 32 bytes of os.urandom() — a fresh,
        cryptographically secure random draw every iteration.
        start_index is used only for batch bookkeeping.
        """
        idx = start_index
        while True:
            entropy = os.urandom(32)
            mnemonic = entropy_to_mnemonic_24(entropy)
            yield (idx, mnemonic)
            idx += 1
