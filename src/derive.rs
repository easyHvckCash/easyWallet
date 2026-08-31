//! BIP39 mnemonic → BIP32 derivation → Bitcoin address
//! Strategy: BIP44 + BIP49 + BIP84 (skip BIP86 Taproot, only 0.75% of BTC)
//! Optimization: thread_local Secp256k1 context + precomputed DerivationPath

use bip39::Mnemonic;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::key::{CompressedPublicKey, PublicKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use bitcoin::Address;
use sha2::{Sha256, Digest};
use std::str::FromStr;

pub const PATHS_LABEL: &str = "BIP44 + BIP49 + BIP84";
pub const PATHS_COVERAGE: &str = "85.14% BTC supply";
pub const PATHS_COUNT: u32 = 3;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LineType {
    Mnemonic,
    PrivateKey,
    Invalid,
}

#[allow(dead_code)]
pub fn detect_line_type(line: &str) -> LineType {
    let s = line.trim();
    if s.is_empty() {
        return LineType::Invalid;
    }
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return LineType::PrivateKey;
    }
    if (s.starts_with('5') || s.starts_with('K') || s.starts_with('L'))
        && s.len() >= 51
        && s.len() <= 52
        && s.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return LineType::PrivateKey;
    }
    let words: Vec<&str> = s.split_whitespace().collect();
    let wc = words.len();
    if wc == 12 || wc == 15 || wc == 18 || wc == 24 {
        if words.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase())) {
            return LineType::Mnemonic;
        }
    }
    LineType::Invalid
}

/// Strict version with full BIP39 checksum validation (for bench/convert tools)
#[allow(dead_code)]
pub fn detect_line_type_strict(line: &str) -> LineType {
    let s = line.trim();
    if s.is_empty() {
        return LineType::Invalid;
    }
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return LineType::PrivateKey;
    }
    if (s.starts_with('5') || s.starts_with('K') || s.starts_with('L'))
        && s.len() >= 51
        && s.len() <= 52
        && s.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return LineType::PrivateKey;
    }
    let words: Vec<&str> = s.split_whitespace().collect();
    if words.len() == 12 || words.len() == 15 || words.len() == 18 || words.len() == 24 {
        if Mnemonic::parse(s).is_ok() {
            return LineType::Mnemonic;
        }
    }
    LineType::Invalid
}

thread_local! {
    pub static SECP: Secp256k1<bitcoin::secp256k1::All> = Secp256k1::new();
    static PATHS: Vec<DerivationPath> = vec![
        DerivationPath::from_str("m/44'/0'/0'/0").unwrap(),
        DerivationPath::from_str("m/49'/0'/0'/0").unwrap(),
        DerivationPath::from_str("m/84'/0'/0'/0").unwrap(),
    ];
}

/// CPU mode: derive all addresses from mnemonic (PBKDF2 + key derivation)
pub fn derive_addresses(mnemonic_str: &str, depth: u32) -> Vec<String> {
    let mnemonic = match Mnemonic::parse(mnemonic_str) {
        Ok(m) => m,
        Err(_) => return vec![],
    };
    let seed = mnemonic.to_seed("");
    derive_from_seed_slice(&seed, depth)
}

/// CUDA mode: derive addresses from GPU-returned seed (skip PBKDF2)
pub fn derive_from_seed(seed: &[u8; 64], depth: u32) -> Vec<String> {
    derive_from_seed_slice(seed, depth)
}

fn derive_from_seed_slice(seed: &[u8], depth: u32) -> Vec<String> {
    let mut addrs = Vec::with_capacity((depth * PATHS_COUNT) as usize);

    SECP.with(|secp| {
        let master = match Xpriv::new_master(Network::Bitcoin, seed) {
            Ok(m) => m,
            Err(_) => return,
        };

        PATHS.with(|paths| {
            for (path_idx, path) in paths.iter().enumerate() {
                let parent = match master.derive_priv(secp, path) {
                    Ok(k) => k,
                    Err(_) => continue,
                };

                for idx in 0..depth {
                    let child_num = ChildNumber::from_normal_idx(idx).unwrap();
                    let child_path = DerivationPath::from(vec![child_num]);
                    let child = match parent.derive_priv(secp, &child_path) {
                        Ok(k) => k,
                        Err(_) => continue,
                    };

                    let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(
                        secp,
                        &child.private_key,
                    );

                    let addr_str = match path_idx {
                        0 => {
                            let pk = PublicKey::new(pubkey);
                            Address::p2pkh(pk, Network::Bitcoin).to_string()
                        }
                        1 => {
                            let cpk = CompressedPublicKey(pubkey);
                            Address::p2shwpkh(&cpk, Network::Bitcoin).to_string()
                        }
                        _ => {
                            let cpk = CompressedPublicKey(pubkey);
                            Address::p2wpkh(&cpk, Network::Bitcoin).to_string()
                        }
                    };

                    addrs.push(addr_str);
                }
            }
        });
    });

    addrs
}

/// Encode GPU-returned hash160 data into address strings
/// h160_data layout: [mnemonic0_path0_idx0(20B), mnemonic0_path0_idx1(20B), ..., mnemonic0_path1_idx0(20B), ...]
/// Order: for each mnemonic, arranged by path_idx(0,1,2) x depth(0..depth)
pub fn addresses_from_h160(h160_data: &[u8], mnemonic_idx: usize, num_paths: usize, depth: u32) -> Vec<String> {
    let addrs_per_mnemonic = num_paths * (depth as usize);
    let offset = mnemonic_idx * addrs_per_mnemonic * 20;
    let mut addrs = Vec::with_capacity(addrs_per_mnemonic);

    for path_idx in 0..num_paths {
        for d in 0..depth as usize {
            let addr_offset = offset + (path_idx * (depth as usize) + d) * 20;
            if addr_offset + 20 > h160_data.len() {
                continue;
            }
            let h160 = &h160_data[addr_offset..addr_offset + 20];
            let addr_str = encode_h160_to_address(h160, path_idx);
            addrs.push(addr_str);
        }
    }

    addrs
}

/// Encode 20-byte hash160 to Bitcoin address
pub fn encode_h160_to_address(h160: &[u8], path_idx: usize) -> String {
    match path_idx {
        0 => {
            // P2PKH: Base58Check(0x00 + hash160)
            let mut payload = vec![0x00u8];
            payload.extend_from_slice(h160);
            base58check_encode(&payload)
        }
        1 => {
            // P2SH-P2WPKH: Base58Check(0x05 + HASH160(0x0014 + hash160))
            let mut redeem = vec![0x00u8, 0x14u8];
            redeem.extend_from_slice(h160);
            let sha = Sha256::digest(&redeem);
            let ripe = ripemd160_hash(&sha);
            let mut payload = vec![0x05u8];
            payload.extend_from_slice(&ripe);
            base58check_encode(&payload)
        }
        _ => {
            // P2WPKH: bech32 encoding
            bech32_encode(h160)
        }
    }
}

fn base58check_encode(payload: &[u8]) -> String {
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(&hash1);
    let mut full = payload.to_vec();
    full.extend_from_slice(&hash2[..4]);
    bs58::encode(full).into_string()
}

fn ripemd160_hash(data: &[u8]) -> [u8; 20] {
    use bitcoin::hashes::{ripemd160, Hash};
    let hash = ripemd160::Hash::hash(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(hash.as_ref());
    out
}

/// Public wrapper for main.rs h160 matching
pub fn ripemd160_hash_pub(data: &[u8]) -> [u8; 20] {
    ripemd160_hash(data)
}

fn bech32_encode(h160: &[u8]) -> String {
    use bitcoin::hashes::Hash;
    use bitcoin::ScriptBuf;
    let inner = bitcoin::hashes::hash160::Hash::from_slice(h160).unwrap();
    let wpkh = bitcoin::WPubkeyHash::from_raw_hash(inner);
    let script = ScriptBuf::new_p2wpkh(&wpkh);
    Address::from_script(&script, Network::Bitcoin)
        .map(|a| a.to_string())
        .unwrap_or_default()
}

/// Derive per-path private keys (WIF) + addresses from mnemonic
pub fn derive_privkeys_from_mnemonic(mnemonic_str: &str, depth: u32) -> Result<Vec<DerivedKey>, String> {
    let mnemonic = Mnemonic::parse(mnemonic_str)
        .map_err(|e| format!("Invalid mnemonic: {}", e))?;
    let seed = mnemonic.to_seed("");
    derive_privkeys_from_seed(&seed, depth)
}

pub struct DerivedKey {
    pub path: String,
    pub privkey_wif: String,
    pub privkey_hex: String,
    pub address: String,
}

fn derive_privkeys_from_seed(seed: &[u8], depth: u32) -> Result<Vec<DerivedKey>, String> {
    let mut results = Vec::new();

    SECP.with(|secp| {
        let master = match Xpriv::new_master(Network::Bitcoin, seed) {
            Ok(m) => m,
            Err(e) => {
                results.push(DerivedKey {
                    path: "error".into(),
                    privkey_wif: format!("{}", e),
                    privkey_hex: String::new(),
                    address: String::new(),
                });
                return;
            }
        };

        let path_strs = ["m/44'/0'/0'/0", "m/49'/0'/0'/0", "m/84'/0'/0'/0"];
        let path_labels = ["P2PKH (1...)", "P2SH-P2WPKH (3...)", "P2WPKH (bc1...)"];

        PATHS.with(|paths| {
            for (path_idx, path) in paths.iter().enumerate() {
                let parent = match master.derive_priv(secp, path) {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                for idx in 0..depth {
                    let child_num = ChildNumber::from_normal_idx(idx).unwrap();
                    let child_path = DerivationPath::from(vec![child_num]);
                    let child = match parent.derive_priv(secp, &child_path) {
                        Ok(k) => k,
                        Err(_) => continue,
                    };
                    let secret_bytes = child.private_key.secret_bytes();
                    let privkey_hex = hex_encode(&secret_bytes);
                    let privkey_wif = wif_encode(&secret_bytes, true);
                    let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(secp, &child.private_key);
                    let addr_str = match path_idx {
                        0 => {
                            let pk = PublicKey::new(pubkey);
                            Address::p2pkh(pk, Network::Bitcoin).to_string()
                        }
                        1 => {
                            let cpk = CompressedPublicKey(pubkey);
                            Address::p2shwpkh(&cpk, Network::Bitcoin).to_string()
                        }
                        _ => {
                            let cpk = CompressedPublicKey(pubkey);
                            Address::p2wpkh(&cpk, Network::Bitcoin).to_string()
                        }
                    };
                    results.push(DerivedKey {
                        path: format!("{}/{} [{}]", path_strs[path_idx], idx, path_labels[path_idx]),
                        privkey_wif,
                        privkey_hex,
                        address: addr_str,
                    });
                }
            }
        });
    });

    Ok(results)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn wif_encode(privkey: &[u8; 32], compressed: bool) -> String {
    let mut payload = vec![0x80u8];
    payload.extend_from_slice(privkey);
    if compressed {
        payload.push(0x01);
    }
    let hash1 = Sha256::digest(&payload);
    let hash2 = Sha256::digest(&hash1);
    payload.extend_from_slice(&hash2[..4]);
    bs58::encode(payload).into_string()
}
