#!/usr/bin/env node
/**
 * CryptoJS MWC verification script - for cross-checking Python POC output
 * Precisely reproduces crypto-js 3.x WordArray.random(16) behavior
 * 
 * Usage: node verify_mwc.js <seed_int> <sign_bits_int>
 * Output: 16 bytes hex (cross-check against Python POC)
 */

function cryptojs_random_16(seed, signBits) {
    // Faithful reproduction of CryptoJS WordArray.random(16)
    // with Math.random() replaced by deterministic seed + sign bits
    var words = [];

    var r = (function (m_w) {
        var m_w = m_w;
        var m_z = 0x3ade68b1;
        var mask = 0xffffffff;

        return function (signBit) {
            m_z = (0x9069 * (m_z & 0xFFFF) + (m_z >> 0x10)) & mask;
            m_w = (0x4650 * (m_w & 0xFFFF) + (m_w >> 0x10)) & mask;
            var result = ((m_z << 0x10) + m_w) & mask;
            result /= 0x100000000;
            result += 0.5;
            return result * (signBit ? 1 : -1);
        }
    });

    var rcache = 0;
    for (var i = 0; i < 4; i++) {
        var m_w_init;
        if (i === 0) {
            m_w_init = seed;  // First round: direct seed
        } else {
            m_w_init = (rcache * 0x100000000) | 0;  // Subsequent: from rcache
        }

        var _r = r(m_w_init);

        var signIdx = i * 2;
        var s1 = (signBits >> (7 - signIdx)) & 1;
        var s2 = (signBits >> (7 - signIdx - 1)) & 1;

        var rcacheFloat = _r(s1);
        rcache = rcacheFloat * 0x3ade67b7;

        var wordFloat = _r(s2);
        var word = (wordFloat * 0x100000000) | 0;
        words.push(word);
    }

    // Convert words to hex bytes (big-endian per word)
    var hex = '';
    for (var w = 0; w < 4; w++) {
        var val = words[w] >>> 0;  // unsigned
        hex += ('00000000' + val.toString(16)).slice(-8);
    }
    return hex;
}

// Main
var seed = parseInt(process.argv[2] || '0');
var signBits = parseInt(process.argv[3] || '0');

console.log('seed=' + seed + ' signs=' + signBits + ' → ' + cryptojs_random_16(seed, signBits));

// Run test suite
var testCases = [
    [0, 0], [0, 255], [1, 0], [12345, 0xAA],
    [0x7FFFFFFF, 0x55], [0xFFFFFFFF, 0xFF],
    [987654321, 170], [1000000, 85]
];

console.log('\n=== Cross-validation test vectors ===');
for (var t of testCases) {
    console.log('seed=' + t[0] + ' signs=' + t[1] + ' → ' + cryptojs_random_16(t[0], t[1]));
}
