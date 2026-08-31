#!/usr/bin/env python3
"""
Python cross-validation script - outputs results for same test cases as verify_mwc.js
Used to confirm Python port equivalence with the original JavaScript implementation

Usage: python3 verify_mwc.py
"""
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from generator import generate_entropy_128

test_cases = [
    (0, 0), (0, 255), (1, 0), (12345, 0xAA),
    (0x7FFFFFFF, 0x55), (0xFFFFFFFF, 0xFF),
    (987654321, 170), (1000000, 85)
]

print("=== Cross-validation test vectors (Python) ===")
for seed, signs in test_cases:
    entropy = generate_entropy_128(seed, signs)
    print(f"seed={seed} signs={signs} → {entropy.hex()}")
