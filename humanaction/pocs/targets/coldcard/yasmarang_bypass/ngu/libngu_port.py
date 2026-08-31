"""
Faithful Python port of Coldcard libngu ngu/random.c

Source: external/libngu/libngu-0ae74d18.../ngu/random.c
All uint32 semantics preserved (mod 2**32).

This is a PORT, not a re-imagination. Line references to the C source are
given so every operation can be diffed against the original.
"""

M32 = 0xFFFFFFFF


class Yasmarang:
    """ngu/random.c L50-L61  --  my_yasmarang()

    NOTE the initial state is HARDCODED in the C source and is never
    seeded from any entropy source:
        static uint32_t yasmarang_pad = 0x0a8ce26f, yasmarang_n = 69,
                        yasmarang_d = 233;
        static uint8_t  yasmarang_dat = 0;
    """

    # ngu/random.c L50-L51 -- verbatim
    INIT_PAD = 0x0A8CE26F
    INIT_N = 69
    INIT_D = 233
    INIT_DAT = 0

    def __init__(self, pad=None, n=None, d=None, dat=None):
        self.pad = self.INIT_PAD if pad is None else pad
        self.n = self.INIT_N if n is None else n
        self.d = self.INIT_D if d is None else d
        self.dat = self.INIT_DAT if dat is None else dat

    def next(self):
        # yasmarang_pad += yasmarang_dat + yasmarang_d * yasmarang_n;
        self.pad = (self.pad + self.dat + (self.d * self.n)) & M32
        # yasmarang_pad = (yasmarang_pad << 3) + (yasmarang_pad >> 29);
        self.pad = (((self.pad << 3) & M32) + (self.pad >> 29)) & M32
        # yasmarang_n = yasmarang_pad | 2;
        self.n = self.pad | 2
        # yasmarang_d ^= (yasmarang_pad << 31) + (yasmarang_pad >> 1);
        self.d ^= (((self.pad << 31) & M32) + (self.pad >> 1)) & M32
        self.d &= M32
        # yasmarang_dat ^= (char)yasmarang_pad ^ (yasmarang_d >> 8) ^ 1;
        # dat is uint8_t, so only the low 8 bits survive the assignment.
        # (char) signedness is therefore irrelevant.
        self.dat = (self.dat ^ (self.pad & 0xFF) ^ ((self.d >> 8) & 0xFF) ^ 1) & 0xFF
        # return pad ^ (d << 5) ^ (pad >> 18) ^ (dat << 1);
        return (
            self.pad ^ ((self.d << 5) & M32) ^ (self.pad >> 18) ^ (self.dat << 1)
        ) & M32


class TrngFault(Exception):
    """Stands in for mp_raise_OSError(MP_EFAULT) / MP_EEXIST."""


def my_random_bytes(count, chip_trng_32, yas):
    """ngu/random.c L63-L84  --  my_random_bytes()

    void my_random_bytes(uint8_t *dest, uint32_t count) {
        uint32_t last = 0;                  // <-- LOCAL, reset every call
        while(count) {
            uint32_t chip = CHIP_TRNG_32();
            if(chip == last) {
                mp_raise_OSError(MP_EFAULT);   // "maybe TRNG is not clocked?"
            }
            last = chip;
            chip ^= my_yasmarang();            // <-- whitening AFTER the check
            int here = MIN(4, count);
            memcpy(dest, &chip, here);
            dest += here; count -= here;
        }
    }
    """
    out = bytearray()
    last = 0  # L65: local, so the check never spans two calls
    remaining = count
    while remaining:
        chip = chip_trng_32() & M32
        if chip == last:  # L70
            raise TrngFault("MP_EFAULT: TRNG not clocked")
        last = chip  # L74
        chip ^= yas.next()  # L76  whitening
        chip &= M32
        here = min(4, remaining)
        out += chip.to_bytes(4, "little")[:here]  # memcpy of uint32, LE on ARM
        remaining -= here
    return bytes(out)


def _bit_length(x):
    """ngu/random.c L98-L107"""
    if not x:
        return 0
    bits = 1
    while x >> bits:
        bits += 1
    return bits


def _rand_below(mx, chip_trng_32, yas):
    """ngu/random.c L109-L130  --  _rand_below()

    Note CHIP_TRNG_32() is consulted exactly ONCE (L120); every rejection
    retry re-randomises using yasmarang only (L128).
    """
    if mx <= 1:
        return 0
    bl = _bit_length(mx)
    assert bl and (bl < 31)  # L114
    mask = ((2 << bl) - 1) & M32  # L118
    pt = yas.next()  # L119
    pt ^= chip_trng_32() & M32  # L120
    pt &= M32
    while True:
        rv = pt & mask  # L123
        if rv < mx:
            return rv
        pt ^= yas.next()  # L128
        pt &= M32
