#!/usr/bin/env python3
"""
Cross-validation: compare custom MT19937 implementation with Python standard random module output.
Ensures POC-generated private keys match actual random.getrandbits(256) output.
"""
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generator import MT19937, privkey_from_seed

test_seeds = [
    0, 1, 42, 1337,
    1231006505,   # Bitcoin genesis
    1388534400,   # 2014-01-01
    1420070400,   # 2015-01-01
    0x7FFFFFFF,   # max int31
    0xFFFFFFFF,   # max uint32
    1609459200,   # 2021-01-01
]

print("=== MT19937 Cross-validation ===")
print(f"{'seed':>12} | {'stdlib getrandbits(256)':>66} | {'our MT19937':>66} | match")
print("-" * 160)

all_match = True
for seed in test_seeds:
    # Python stdlib
    random.seed(seed)
    stdlib_result = random.getrandbits(256)

    # Our implementation
    mt = MT19937(seed)
    our_result = mt.getrandbits(256)

    match = stdlib_result == our_result
    if not match:
        all_match = False

    # Show first/last 8 hex chars for readability
    s_hex = f"{stdlib_result:064x}"
    o_hex = f"{our_result:064x}"
    print(f"{seed:>12} | {s_hex[:32]}...{s_hex[-8:]} | {o_hex[:32]}...{o_hex[-8:]} | {'✓' if match else '✗ MISMATCH'}")

print()
if all_match:
    print("ALL PASSED — MT19937 implementation is equivalent to Python stdlib")
else:
    print("FAILED — implementation mismatch detected!")
    sys.exit(1)

# Additional: verify privkey generation
print("\n=== Private Key Generation Test ===")
for seed in [1231006505, 1388534400, 1420070400]:
    pk = privkey_from_seed(seed)
    print(f"seed={seed} (ts) → privkey={pk[:16]}...{pk[-8:]}")
