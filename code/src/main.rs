//! BTC Mnemonic Scanner v0.3 - Full GPU Pipeline
//! P0: secp256k1 + BIP32 fully on GPU
//! P1: Double-buffered CUDA stream pipeline (ping-pong overlap)
//! P3: BinaryFuse8 filter matching on GPU
//! P4: Optimized SHA-512 (midstate pre-computation, unrolled)

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Child, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::Json;
use clap::Parser;
use rusqlite::Connection;
use rayon::prelude::*;
use serde::{Serialize, Deserialize};
use siphasher::sip::SipHasher13;
use sysinfo::System;
use xorf::{BinaryFuse8, DmaSerializable, Filter};

pub mod derive;
pub mod cuda;
pub mod protocol;
pub mod master;
pub mod node;

#[derive(Parser, Clone)]
#[command(name = "btc-cuda-scanner")]
#[command(about = "BIP39 mnemonic scanner - Distributed Master/Node architecture")]
pub struct Args {
    /// Role: master | node
    #[arg(long)]
    pub role: String,

    /// Master listen port (role=master)
    #[arg(long, default_value = "8877")]
    pub listenon: u16,

    /// Master address (role=node), e.g. 192.168.1.1:8877
    #[arg(long)]
    pub server: Option<String>,

    /// Cluster communication token
    #[arg(long, default_value = "changeme")]
    pub token: String,

    /// Working directory (contains waittocheck/, results/)
    #[arg(short = 'F', long = "folder", default_value = "files")]
    pub folder: PathBuf,

    /// Derivation depth (index per path)
    #[arg(long, default_value = "3")]
    pub depth: u32,

    /// Web panel port (master dashboard)
    #[arg(short, long, default_value = "7891")]
    pub port: u16,

    /// Parallel threads (0=CPU cores)
    #[arg(short, long, default_value = "0")]
    pub threads: usize,

    /// Dashboard username (role=master)
    #[arg(long, default_value = "admin")]
    pub user: String,

    /// Dashboard password (role=master)
    #[arg(long, default_value = "admin")]
    pub passwd: String,
}

impl Args {
    fn utxo_file(&self) -> PathBuf {
        PathBuf::from("../humanaction/addr").join("utxo_addresses.set")
    }
    fn watch_dir(&self) -> PathBuf {
        self.folder.join("waittocheck")
    }
}

#[derive(Serialize, Clone)]
struct Stats {
    mode: &'static str,
    gpu_name: String,
    gpu_available: bool,
    use_gpu: bool,
    status: String,
    running: bool,
    bench_running: bool,
    total_mnemonics: u64,
    total_hits: u64,
    speed_mps: f64,
    elapsed_seconds: f64,
    utxo_set_size: usize,
    threads: usize,
    depth: u32,
    paths: &'static str,
    paths_coverage: &'static str,
    addrs_per_mnemonic: u32,
    current_file: String,
    pending_files: usize,
    pending_by_dir: HashMap<String, usize>,
}

struct AppState {
    counter: AtomicU64,
    hits: AtomicU64,
    start: Instant,
    utxo_size: usize,
    threads: usize,
    depth: u32,
    current_file: Mutex<String>,
    pending_files: AtomicU64,
    pending_by_dir: Mutex<HashMap<String, usize>>,
    status: Mutex<String>,
    mode: &'static str,
    gpu_name: String,
    gpu_available: bool,
    dir_stats: Mutex<DirStatsMap>,
    gpu: Option<Mutex<cuda::GpuAccelerator>>,
    running: AtomicBool,
    use_gpu: AtomicBool,
    utxo_set: Arc<UtxoFilter>,
    // Benchmark
    bench_running: AtomicBool,
    bench_log: Mutex<Vec<String>>,
    bench_done: AtomicBool,
    // System monitor
    sys: Mutex<System>,
    hostname: String,
    cpu_name: String,
    total_memory_mb: u64,
    // POC management
    poc_manager: Mutex<PocManager>,
    poc_base_dir: PathBuf,
    scanner_folder: PathBuf,
    db_path: PathBuf,
    // POC type mapping: poc_id -> "mnemonic" | "privkey"
    poc_type_map: HashMap<String, String>,
    // POC reload
    last_reload_time: Mutex<Option<String>>,
    reload_reason: Mutex<Option<String>>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct DirStatsEntry {
    files_processed: u64,
    mnemonics_scanned: u64,
    privkeys_scanned: u64,
    hits: u64,
    last_file: String,
    last_time: String,
}

type DirStatsMap = HashMap<String, DirStatsEntry>;

#[allow(dead_code)]
struct PocProcess {
    child: Child,
    poc_id: String,
    poc_name: String,
    output_dir: String,
    start_time: Instant,
}

struct PocManager {
    processes: HashMap<String, PocProcess>,
    max_concurrent: usize,
    maxfile: u32,
}

impl PocManager {
    fn new(max: usize) -> Self {
        Self { processes: HashMap::new(), max_concurrent: max, maxfile: 200 }
    }
    fn active_count(&self) -> usize {
        self.processes.len()
    }
}

fn load_dir_stats(db_path: &PathBuf) -> DirStatsMap {
    let mut map = HashMap::new();
    if let Ok(conn) = Connection::open(db_path) {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT dir_label, files_processed, mnemonics_scanned, hits, last_file, last_time, \
             COALESCE(privkeys_scanned,0) FROM dir_stats"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    DirStatsEntry {
                        files_processed: row.get::<_, i64>(1)? as u64,
                        mnemonics_scanned: row.get::<_, i64>(2)? as u64,
                        hits: row.get::<_, i64>(3)? as u64,
                        last_file: row.get::<_, String>(4)?,
                        last_time: row.get::<_, String>(5)?,
                        privkeys_scanned: row.get::<_, i64>(6)? as u64,
                    },
                ))
            }) {
                for row in rows.flatten() {
                    map.insert(row.0, row.1);
                }
            }
        }
    }
    map
}

fn save_dir_stats(db_path: &PathBuf, stats: &DirStatsMap) {
    if let Ok(conn) = Connection::open(db_path) {
        for (label, entry) in stats.iter() {
            let _ = conn.execute(
                "INSERT INTO dir_stats (dir_label, files_processed, mnemonics_scanned, hits, last_file, last_time, privkeys_scanned) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                 ON CONFLICT(dir_label) DO UPDATE SET files_processed=?2, mnemonics_scanned=?3, hits=?4, last_file=?5, last_time=?6, privkeys_scanned=?7",
                rusqlite::params![label, entry.files_processed as i64, entry.mnemonics_scanned as i64, entry.hits as i64, entry.last_file, entry.last_time, entry.privkeys_scanned as i64],
            );
        }
    }
}

/// Build poc_id -> output_type mapping from pocinfo.json
fn load_poc_type_map(poc_base_dir: &PathBuf) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let path = poc_base_dir.join("pocinfo.json");
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return map,
    };
    let data: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return map,
    };
    if let Some(vendors) = data.as_object() {
        for vendor_data in vendors.values() {
            if let Some(pocs) = vendor_data.get("pocs").and_then(|p| p.as_array()) {
                for poc in pocs {
                    if let (Some(id), Some(ot)) = (
                        poc.get("id").and_then(|v| v.as_str()),
                        poc.get("output_type").and_then(|v| v.as_str()),
                    ) {
                        map.insert(id.to_string(), ot.to_string());
                    }
                }
            }
        }
    }
    map
}

// --- Public interface for node.rs ---

// UtxoFilter is pub struct defined below

/// Load UTXO filter from the standard path (../humanaction/addr/utxo_addresses.set)
pub fn load_utxo_filter(_folder: &PathBuf) -> Arc<UtxoFilter> {
    let path = PathBuf::from("../humanaction/addr").join("utxo_addresses.set");
    let filter = load_utxo_set(&path);
    Arc::new(filter)
}

/// Try to initialize GPU accelerator, returns None if unavailable
pub fn try_init_gpu(_folder: &PathBuf) -> Option<std::sync::Mutex<cuda::GpuAccelerator>> {
    let path = PathBuf::from("../humanaction/addr").join("utxo_addresses.set");
    let utxo_set = load_utxo_set(&path);
    try_init_gpu_with_filter(&utxo_set)
}

pub fn try_init_gpu_with_filter(utxo_set: &UtxoFilter) -> Option<std::sync::Mutex<cuda::GpuAccelerator>> {
    let cuda_ctx = cuda::CudaDetect::init();
    if !cuda_ctx.is_available() || !cuda::kernel_ready() {
        return None;
    }

    let gpu_filter = cuda::GpuFilterData {
        segment_length: utxo_set.fuse_segment_length(),
        segment_count_length: utxo_set.fuse_segment_count_length(),
        segment_length_mask: utxo_set.fuse_segment_length_mask(),
        array_length: utxo_set.fuse_array_length(),
        seed: utxo_set.fuse_seed(),
        fingerprints: utxo_set.fuse_fingerprints().to_vec(),
    };

    match cuda::GpuAccelerator::new(Some(&gpu_filter)) {
        Ok(acc) => {
            println!("[CUDA] GPU accelerator ready: {}", acc.mode_label());
            Some(std::sync::Mutex::new(acc))
        }
        Err(e) => {
            println!("[CUDA] GPU init failed: {}, using CPU", e);
            None
        }
    }
}

/// Scan a batch of mnemonics, return Vec<(mnemonic, address)> for hits
pub fn scan_mnemonics_batch(
    mnemonics: &[String],
    depth: u32,
    utxo_set: &Arc<UtxoFilter>,
    gpu: &Option<std::sync::Mutex<cuda::GpuAccelerator>>,
) -> Vec<(String, String)> {
    let mut hits = Vec::new();

    if let Some(ref gpu_lock) = gpu {
        let has_full = gpu_lock.lock().unwrap().has_full_pipeline();
        if has_full {
            let batch_size = gpu_lock.lock().unwrap().max_batch_size() as usize;
            for chunk in mnemonics.chunks(batch_size) {
                let acc = gpu_lock.lock().unwrap();
                match acc.derive_h160_launch(chunk, depth, false) {
                    Ok(pending) => {
                        drop(acc);
                        match pending.collect() {
                            Ok(h160_data) => {
                                let num_paths = derive::PATHS_COUNT as usize;
                                for (i, mnemonic) in chunk.iter().enumerate() {
                                    let found = match_h160_for_node(&h160_data, i, num_paths, depth, utxo_set);
                                    for addr in found {
                                        hits.push((mnemonic.clone(), addr));
                                    }
                                }
                            }
                            Err(_) => {
                                // Fallback to CPU for this chunk
                                for m in chunk {
                                    let addrs = derive::derive_addresses(m, depth);
                                    for a in &addrs {
                                        if utxo_set.contains(a) {
                                            hits.push((m.clone(), a.clone()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        drop(acc);
                        for m in chunk {
                            let addrs = derive::derive_addresses(m, depth);
                            for a in &addrs {
                                if utxo_set.contains(a) {
                                    hits.push((m.clone(), a.clone()));
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // GPU without full pipeline, fallback to CPU
            scan_mnemonics_cpu(mnemonics, depth, utxo_set, &mut hits);
        }
    } else {
        scan_mnemonics_cpu(mnemonics, depth, utxo_set, &mut hits);
    }

    hits
}

fn scan_mnemonics_cpu(
    mnemonics: &[String],
    depth: u32,
    utxo_set: &Arc<UtxoFilter>,
    hits: &mut Vec<(String, String)>,
) {
    use rayon::prelude::*;
    let results: Vec<(String, String)> = mnemonics.par_iter().flat_map(|m| {
        let addrs = derive::derive_addresses(m, depth);
        addrs.into_iter()
            .filter(|a| utxo_set.contains(a))
            .map(|a| (m.clone(), a))
            .collect::<Vec<_>>()
    }).collect();
    hits.extend(results);
}

fn match_h160_for_node(
    h160_data: &[u8],
    mnemonic_idx: usize,
    num_paths: usize,
    depth: u32,
    utxo_set: &Arc<UtxoFilter>,
) -> Vec<String> {
    use sha2::{Sha256, Digest};
    let mut matched = Vec::new();
    let addrs_per_mnemonic = num_paths * (depth as usize);
    let base_offset = mnemonic_idx * addrs_per_mnemonic * 20;

    for path_idx in 0..num_paths {
        for d in 0..depth as usize {
            let offset = base_offset + (path_idx * (depth as usize) + d) * 20;
            if offset + 20 > h160_data.len() { continue; }
            let h160: &[u8; 20] = h160_data[offset..offset + 20].try_into().unwrap();

            let hit = if path_idx == 1 {
                let mut redeem = [0u8; 22];
                redeem[0] = 0x00;
                redeem[1] = 0x14;
                redeem[2..].copy_from_slice(h160);
                let sha = Sha256::digest(&redeem);
                let ripe = derive::ripemd160_hash_pub(&sha);
                utxo_set.contains_h160(&ripe)
            } else {
                utxo_set.contains_h160(h160)
            };

            if hit {
                let addr = derive::encode_h160_to_address(h160, path_idx);
                matched.push(addr);
            }
        }
    }
    matched
}

/// Scan a batch of private keys, return Vec<(privkey, address)> for hits
pub fn scan_privkeys_batch(
    privkeys: &[String],
    utxo_set: &Arc<UtxoFilter>,
) -> Vec<(String, String)> {
    use rayon::prelude::*;
    privkeys.par_iter().flat_map(|key_str| {
        if let Ok(addrs) = derive_from_private_key(key_str) {
            addrs.into_iter()
                .filter(|(_, a)| utxo_set.contains(a.as_str()))
                .map(|(_, a)| (key_str.clone(), a))
                .collect::<Vec<_>>()
        } else {
            vec![]
        }
    }).collect()
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .unwrap();
    }

    match args.role.as_str() {
        "master" => {
            println!("========================================");
            println!("  easyWallet - MASTER MODE");
            println!("  Cluster port: {}", args.listenon);
            println!("========================================");
            master::run_master(args).await;
        }
        "node" => {
            if args.server.is_none() {
                eprintln!("Error: --server is required for node role");
                std::process::exit(1);
            }
            println!("========================================");
            println!("  easyWallet - NODE MODE");
            println!("  Master: {}", args.server.as_ref().unwrap());
            println!("========================================");
            node::run_node(args).await;
        }
        other => {
            eprintln!("Error: unknown role '{}'. Use 'master' or 'node'", other);
            std::process::exit(1);
        }
    }
}


fn addr_to_hash(addr: &str) -> u64 {
    let mut h = SipHasher13::new_with_keys(0xB7C5CA4, 0xF117E3);
    addr.hash(&mut h);
    h.finish()
}

fn h160_to_hash(h160: &[u8]) -> u64 {
    let mut h = SipHasher13::new_with_keys(0xB7C5CA4, 0xF117E3);
    h160.hash(&mut h);
    h.finish()
}

/// Decode hash160 (20 bytes) from a bitcoin address
fn decode_address_to_h160(addr: &str) -> Option<[u8; 20]> {
    if addr.starts_with('1') || addr.starts_with('3') {
        // Base58Check: version(1) + hash160(20) + checksum(4)
        let decoded = bs58::decode(addr).into_vec().ok()?;
        if decoded.len() == 25 {
            let mut h160 = [0u8; 20];
            h160.copy_from_slice(&decoded[1..21]);
            Some(h160)
        } else {
            None
        }
    } else if addr.starts_with("bc1q") && addr.len() == 42 {
        // P2WPKH bech32: decode witness program (20 bytes)
        use bitcoin::Address;
        let parsed = Address::from_str(addr).ok()?;
        let addr_uc = parsed.assume_checked();
        let script = addr_uc.script_pubkey();
        let bytes = script.as_bytes();
        // P2WPKH script: OP_0(0x00) OP_PUSH20(0x14) <20 bytes>
        if bytes.len() == 22 && bytes[0] == 0x00 && bytes[1] == 0x14 {
            let mut h160 = [0u8; 20];
            h160.copy_from_slice(&bytes[2..22]);
            Some(h160)
        } else {
            None
        }
    } else {
        None
    }
}

pub struct UtxoFilter {
    filter: BinaryFuse8,
    fallback: HashSet<String>,
    // h160 direct matching (skip address encoding in full-pipeline GPU path)
    h160_filter: Option<BinaryFuse8>,
    h160_fallback: HashSet<[u8; 20]>,
    size: usize,
}

impl UtxoFilter {
    fn contains(&self, addr: &str) -> bool {
        let h = addr_to_hash(addr);
        if self.filter.contains(&h) {
            self.fallback.contains(addr)
        } else {
            false
        }
    }

    /// Direct h160 byte matching - skip address encoding, used by GPU path
    fn contains_h160(&self, h160: &[u8; 20]) -> bool {
        if let Some(ref f) = self.h160_filter {
            let h = h160_to_hash(h160);
            if f.contains(&h) {
                self.h160_fallback.contains(h160)
            } else {
                false
            }
        } else {
            false
        }
    }

    fn has_h160_filter(&self) -> bool {
        self.h160_filter.is_some()
    }

    fn len(&self) -> usize {
        self.size
    }

    fn fuse_segment_length(&self) -> u32 {
        let desc = self.get_descriptor();
        desc.1
    }

    fn fuse_segment_length_mask(&self) -> u32 {
        let desc = self.get_descriptor();
        desc.2
    }

    fn fuse_array_length(&self) -> u32 {
        self.filter.fingerprints.len() as u32
    }

    fn fuse_seed(&self) -> u64 {
        let desc = self.get_descriptor();
        desc.0
    }

    fn fuse_segment_count_length(&self) -> u32 {
        let desc = self.get_descriptor();
        desc.3
    }

    fn fuse_fingerprints(&self) -> &[u8] {
        &self.filter.fingerprints
    }

    fn get_descriptor(&self) -> (u64, u32, u32, u32) {
        let mut buf = [0u8; 20];
        self.filter.dma_copy_descriptor_to(&mut buf);
        let seed = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let seg_len = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let seg_mask = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let seg_count_len = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        (seed, seg_len, seg_mask, seg_count_len)
    }
}

pub fn load_utxo_set(path: &PathBuf) -> UtxoFilter {
    println!("[Load] UTXO file: {:?}", path);
    let t = Instant::now();
    let file = BufReader::new(File::open(path).expect("Cannot open UTXO file"));
    let addrs: Vec<String> = file
        .lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let size = addrs.len();
    let hashes: Vec<u64> = addrs.iter().map(|a| addr_to_hash(a)).collect();

    println!("[Build] BinaryFuse8 filter ({} keys)...", size);
    let filter = BinaryFuse8::try_from(&hashes)
        .expect("BinaryFuse8 build failed");

    // Build h160 direct matching index (skip address encoding)
    // Note: 1-prefix and bc1q store hash160(pubkey)
    //       3-prefix stores HASH160(0x0014||hash160(pubkey)) - i.e. redeem script hash
    // For matching, apply an extra hash layer for path_idx=1
    println!("[Build] h160 direct matching index...");
    let mut h160_set: HashSet<[u8; 20]> = HashSet::with_capacity(size);
    for addr in &addrs {
        if let Some(h160) = decode_address_to_h160(addr) {
            h160_set.insert(h160);
        }
    }
    let h160_hashes: Vec<u64> = h160_set.iter().map(|h| h160_to_hash(h)).collect();
    let h160_filter = if !h160_hashes.is_empty() {
        BinaryFuse8::try_from(&h160_hashes).ok()
    } else {
        None
    };
    println!("[Build] h160 index: {} entries ({:.1}s)", h160_set.len(), t.elapsed().as_secs_f64());

    let fallback: HashSet<String> = addrs.into_iter().collect();
    let mem_filter = (size as f64 * 1.23 * 1.0) / 1024.0 / 1024.0;
    println!(
        "[Load] {} addresses, filter ~{:.1} MB, {:.1}s",
        size, mem_filter, t.elapsed().as_secs_f64()
    );
    println!();

    UtxoFilter { filter, fallback, h160_filter, h160_fallback: h160_set, size }
}

fn run_watch_mode(
    dir: &PathBuf,
    args: &Args,
    utxo_set: &Arc<UtxoFilter>,
    state: &Arc<AppState>,
    output: &Arc<Mutex<File>>,
) {
    println!("[Monitor] Directory: {:?} (scanning configured POC subdirs only)", dir);
    println!("[Wait] Click Start on Web panel to begin scanning...");
    loop {
        if !state.running.load(Ordering::Relaxed) {
            if *state.status.lock().unwrap() != "paused" {
                *state.status.lock().unwrap() = "idle".to_string();
            }
            *state.current_file.lock().unwrap() = String::new();
            std::thread::sleep(std::time::Duration::from_millis(500));
            continue;
        }

        let (files, pending_map) = collect_txt_files_configured(dir, &state.poc_type_map);

        let total_pending: usize = pending_map.values().sum();
        state.pending_files.store(total_pending as u64, Ordering::Relaxed);
        *state.pending_by_dir.lock().unwrap() = pending_map;

        if files.is_empty() {
            *state.status.lock().unwrap() = "waiting (no tasks)".to_string();
            *state.current_file.lock().unwrap() = String::new();
            std::thread::sleep(std::time::Duration::from_secs(3));
            continue;
        }

        let mut files_since_save = 0u32;
        for (file, output_type) in &files {
            if !state.running.load(Ordering::Relaxed) {
                break;
            }
            let dir_label = file_dir_label(file, dir);
            let fname = file.file_name().unwrap().to_string_lossy().to_string();
            let display_name = format!("{}/{}", dir_label, fname);
            *state.current_file.lock().unwrap() = display_name.clone();
            *state.status.lock().unwrap() = format!("processing {}", display_name);

            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let lines: Vec<String> = content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();

            let line_count = lines.len() as u64;
            let hits_before = state.hits.load(Ordering::Relaxed);

            if !lines.is_empty() {
                if output_type == "privkey" {
                    process_privkey_batch(&lines, utxo_set, state, output);
                } else {
                    process_batch(&lines, args, utxo_set, state, output);
                }
            }
            let _ = fs::remove_file(file);

            let hits_after = state.hits.load(Ordering::Relaxed);
            let new_hits = hits_after - hits_before;

            {
                let mut ds = state.dir_stats.lock().unwrap();
                let entry = ds.entry(dir_label.clone()).or_default();
                entry.files_processed += 1;
                if output_type == "privkey" {
                    entry.privkeys_scanned += line_count;
                } else {
                    entry.mnemonics_scanned += line_count;
                }
                entry.hits += new_hits;
                entry.last_file = fname;
                entry.last_time = chrono_now();
                files_since_save += 1;
                if files_since_save >= 10 || new_hits > 0 {
                    save_dir_stats(&state.db_path, &ds);
                    files_since_save = 0;
                }
            }

            // Refresh pending: decrement directly instead of re-scanning directory
            state.pending_files.fetch_sub(1, Ordering::Relaxed);
            {
                let mut pbd = state.pending_by_dir.lock().unwrap();
                if let Some(count) = pbd.get_mut(&dir_label) {
                    *count = count.saturating_sub(1);
                }
            }
        }
    }
}

/// Only scan subdirectories configured in poc_type_map + root dir (default mnemonic)
fn collect_txt_files_configured(dir: &PathBuf, poc_type_map: &HashMap<String, String>) -> (Vec<(PathBuf, String)>, HashMap<String, usize>) {
    let mut files: Vec<(PathBuf, String)> = Vec::new();
    let mut pending_map: HashMap<String, usize> = HashMap::new();

    // Root directory .txt files default to mnemonic type
    if let Ok(rd) = fs::read_dir(dir) {
        for entry in rd.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() && path.extension().map(|e| e == "txt").unwrap_or(false) {
                files.push((path, "mnemonic".to_string()));
                *pending_map.entry(".".to_string()).or_insert(0) += 1;
            }
        }
    }

    // Configured POC subdirectories
    for (poc_id, output_type) in poc_type_map {
        let subdir = dir.join(poc_id);
        if !subdir.is_dir() {
            continue;
        }
        if let Ok(rd) = fs::read_dir(&subdir) {
            for entry in rd.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() && path.extension().map(|e| e == "txt").unwrap_or(false) {
                    files.push((path, output_type.clone()));
                    *pending_map.entry(poc_id.clone()).or_insert(0) += 1;
                }
            }
        }
    }

    use rand::seq::SliceRandom;
    files.shuffle(&mut rand::thread_rng());
    (files, pending_map)
}

fn file_dir_label(file: &PathBuf, watch_root: &PathBuf) -> String {
    if let Some(parent) = file.parent() {
        if parent == watch_root {
            return ".".to_string();
        }
        if let Some(name) = parent.file_name() {
            return name.to_string_lossy().to_string();
        }
    }
    ".".to_string()
}

fn process_batch(
    mnemonics: &[String],
    args: &Args,
    utxo_set: &Arc<UtxoFilter>,
    state: &Arc<AppState>,
    output: &Arc<Mutex<File>>,
) {
    let depth = args.depth;

    if state.gpu.is_some() && state.use_gpu.load(Ordering::Relaxed) {
        process_batch_gpu(mnemonics, depth, utxo_set, state, output);
    } else {
        process_batch_cpu(mnemonics, depth, utxo_set, state, output);
    }
}

fn process_batch_gpu(
    mnemonics: &[String],
    depth: u32,
    utxo_set: &Arc<UtxoFilter>,
    state: &Arc<AppState>,
    output: &Arc<Mutex<File>>,
) {
    let gpu = state.gpu.as_ref().unwrap();
    let batch_size = gpu.lock().unwrap().max_batch_size() as usize;
    // Full pipeline: GPU does PBKDF2+BIP32+secp256k1+hash160, CPU encodes addresses & matches
    let has_full = gpu.lock().unwrap().has_full_pipeline();

    if has_full {
        let chunks: Vec<&[String]> = mnemonics.chunks(batch_size).collect();
        if chunks.is_empty() {
            return;
        }
        let mut use_b = false;

        // Launch first batch (non-blocking)
        let mut pending = {
            let acc = gpu.lock().unwrap();
            match acc.derive_h160_launch(chunks[0], depth, use_b) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[CUDA] derive_h160 launch failed: {}, fallback to CPU", e);
                    process_batch_cpu(mnemonics, depth, utxo_set, state, output);
                    return;
                }
            }
        };
        use_b = !use_b;

        // Pre-launch second batch so GPU never idles
        let mut next_pending = if chunks.len() > 1 {
            let acc = gpu.lock().unwrap();
            acc.derive_h160_launch(chunks[1], depth, use_b).ok()
        } else {
            None
        };
        if next_pending.is_some() { use_b = !use_b; }

        for ci in 1..chunks.len() {
            let h160_data = match pending.collect() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[CUDA] h160 collect failed: {}", e);
                    process_batch_cpu(chunks[ci - 1], depth, utxo_set, state, output);
                    vec![]
                }
            };

            // Promote pre-launched next batch to current
            pending = match next_pending.take() {
                Some(p) => p,
                None => {
                    let acc = gpu.lock().unwrap();
                    match acc.derive_h160_launch(chunks[ci], depth, use_b) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("[CUDA] h160 launch failed: {}", e);
                            process_batch_cpu(chunks[ci], depth, utxo_set, state, output);
                            acc.derive_h160_launch(&[], depth, false).unwrap()
                        }
                    }
                }
            };

            // Pre-launch the batch AFTER next (ci+1) while CPU processes current results
            if ci + 1 < chunks.len() {
                let acc = gpu.lock().unwrap();
                next_pending = acc.derive_h160_launch(chunks[ci + 1], depth, use_b).ok();
                if next_pending.is_some() { use_b = !use_b; }
            }

            // CPU: direct h160 matching (skip address encoding, much faster)
            if !h160_data.is_empty() {
                let prev_c = chunks[ci - 1];
                let num_paths = 3usize;
                let use_h160 = utxo_set.has_h160_filter();
                prev_c.par_iter().enumerate().for_each(|(i, mnemonic)| {
                    state.counter.fetch_add(1, Ordering::Relaxed);
                    if use_h160 {
                        match_h160_direct(&h160_data, i, num_paths, depth, mnemonic, utxo_set, state, output);
                    } else {
                        let addrs = derive::addresses_from_h160(&h160_data, i, num_paths, depth);
                        let matched: Vec<&String> = addrs.iter().filter(|a| utxo_set.contains(a)).collect();
                        if !matched.is_empty() {
                            report_hit(mnemonic, &matched, state, output);
                        }
                    }
                });
            }
        }

        // Process last batch
        if let Ok(h160_data) = pending.collect() {
            if !h160_data.is_empty() {
                let last_c = chunks[chunks.len() - 1];
                let num_paths = 3usize;
                let use_h160 = utxo_set.has_h160_filter();
                last_c.par_iter().enumerate().for_each(|(i, mnemonic)| {
                    state.counter.fetch_add(1, Ordering::Relaxed);
                    if use_h160 {
                        match_h160_direct(&h160_data, i, num_paths, depth, mnemonic, utxo_set, state, output);
                    } else {
                        let addrs = derive::addresses_from_h160(&h160_data, i, num_paths, depth);
                        let matched: Vec<&String> = addrs.iter().filter(|a| utxo_set.contains(a)).collect();
                        if !matched.is_empty() {
                            report_hit(mnemonic, &matched, state, output);
                        }
                    }
                });
            }
        }
    } else {
        // Pipelined: GPU PBKDF2 batch N+1 overlaps with CPU derivation of batch N
        let chunks: Vec<&[String]> = mnemonics.chunks(batch_size).collect();
        if chunks.is_empty() {
            return;
        }
        let mut use_b = false;

        // Launch first GPU batch
        let mut pending = {
            let acc = gpu.lock().unwrap();
            match acc.pbkdf2_launch(chunks[0], use_b) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[CUDA] PBKDF2 launch failed: {}, fallback to CPU", e);
                    process_batch_cpu(mnemonics, depth, utxo_set, state, output);
                    return;
                }
            }
        };
        use_b = !use_b;

        for ci in 1..chunks.len() {
            // Collect previous GPU result
            let seeds = match pending.collect() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[CUDA] collect failed: {}", e);
                    process_batch_cpu(chunks[ci - 1], depth, utxo_set, state, output);
                    vec![]
                }
            };

            // Launch next GPU batch immediately (non-blocking)
            let launch_result = {
                let acc = gpu.lock().unwrap();
                acc.pbkdf2_launch(chunks[ci], use_b)
            };
            pending = match launch_result {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[CUDA] PBKDF2 launch failed: {}", e);
                    process_batch_cpu(chunks[ci], depth, utxo_set, state, output);
                    let acc2 = gpu.lock().unwrap();
                    acc2.pbkdf2_launch(&[], false).unwrap()
                }
            };
            use_b = !use_b;

            // CPU derivation runs while GPU computes next batch
            if !seeds.is_empty() {
                let prev_c = chunks[ci - 1];
                let prev_refs: Vec<&String> = prev_c.iter().collect();
                seeds.into_par_iter().enumerate().for_each(|(i, seed)| {
                    let addrs = derive::derive_from_seed(&seed, depth);
                    state.counter.fetch_add(1, Ordering::Relaxed);
                    let matched: Vec<&String> = addrs.iter().filter(|a| utxo_set.contains(a)).collect();
                    if !matched.is_empty() {
                        report_hit(prev_refs[i], &matched, state, output);
                    }
                });
            }
        }

        // Collect and process the last batch
        let last_idx = chunks.len() - 1;
        if let Ok(seeds) = pending.collect() {
            if !seeds.is_empty() {
                let last_c = chunks[last_idx];
                let last_refs: Vec<&String> = last_c.iter().collect();
                seeds.into_par_iter().enumerate().for_each(|(i, seed)| {
                    let addrs = derive::derive_from_seed(&seed, depth);
                    state.counter.fetch_add(1, Ordering::Relaxed);
                    let matched: Vec<&String> = addrs.iter().filter(|a| utxo_set.contains(a)).collect();
                    if !matched.is_empty() {
                        report_hit(last_refs[i], &matched, state, output);
                    }
                });
            }
        }
    }
}

/// Direct h160 matching: skip address encoding, encode only on hit for reporting
/// path 0 (P2PKH) and path 2 (P2WPKH): GPU's hash160(pubkey) matched directly
/// path 1 (P2SH-P2WPKH): requires extra HASH160(0x0014 || h160) to match 3-prefix addresses
fn match_h160_direct(
    h160_data: &[u8],
    mnemonic_idx: usize,
    num_paths: usize,
    depth: u32,
    mnemonic: &str,
    utxo_set: &Arc<UtxoFilter>,
    state: &Arc<AppState>,
    output: &Arc<Mutex<File>>,
) {
    use sha2::{Sha256, Digest};

    let addrs_per_mnemonic = num_paths * (depth as usize);
    let base_offset = mnemonic_idx * addrs_per_mnemonic * 20;
    let mut matched_addrs: Vec<String> = Vec::new();

    for path_idx in 0..num_paths {
        for d in 0..depth as usize {
            let offset = base_offset + (path_idx * (depth as usize) + d) * 20;
            if offset + 20 > h160_data.len() {
                continue;
            }
            let h160: &[u8; 20] = h160_data[offset..offset + 20].try_into().unwrap();

            let hit = if path_idx == 1 {
                // P2SH-P2WPKH: UTXO stores HASH160(0x0014 || hash160(pubkey))
                let mut redeem = [0u8; 22];
                redeem[0] = 0x00;
                redeem[1] = 0x14;
                redeem[2..].copy_from_slice(h160);
                let sha = Sha256::digest(&redeem);
                let ripe = derive::ripemd160_hash_pub(&sha);
                utxo_set.contains_h160(&ripe)
            } else {
                // P2PKH / P2WPKH: direct match
                utxo_set.contains_h160(h160)
            };

            if hit {
                let addr = derive::encode_h160_to_address(h160, path_idx);
                matched_addrs.push(addr);
            }
        }
    }

    if !matched_addrs.is_empty() {
        let refs: Vec<&String> = matched_addrs.iter().collect();
        report_hit(mnemonic, &refs, state, output);
    }
}

fn process_batch_cpu(
    mnemonics: &[String],
    depth: u32,
    utxo_set: &Arc<UtxoFilter>,
    state: &Arc<AppState>,
    output: &Arc<Mutex<File>>,
) {
    mnemonics.par_iter().for_each(|mnemonic| {
        let addrs = derive::derive_addresses(mnemonic, depth);
        state.counter.fetch_add(1, Ordering::Relaxed);

        let matched: Vec<&String> = addrs.iter().filter(|a| utxo_set.contains(a)).collect();
        if !matched.is_empty() {
            report_hit(mnemonic, &matched, state, output);
        }
    });
}

fn process_privkey_batch(
    privkeys: &[String],
    utxo_set: &Arc<UtxoFilter>,
    state: &Arc<AppState>,
    output: &Arc<Mutex<File>>,
) {
    privkeys.par_iter().for_each(|key_str| {
        state.counter.fetch_add(1, Ordering::Relaxed);
        if let Ok(addrs) = derive_from_private_key(key_str) {
            let matched: Vec<&String> = addrs.iter()
                .map(|(_, a)| a)
                .filter(|a| utxo_set.contains(a.as_str()))
                .collect();
            if !matched.is_empty() {
                report_hit(key_str, &matched, state, output);
            }
        }
    });
}

fn report_hit(
    source: &str,
    matched: &[&String],
    state: &Arc<AppState>,
    _output: &Arc<Mutex<File>>,
) {
    state.hits.fetch_add(matched.len() as u64, Ordering::Relaxed);
    println!(
        "\n  [HIT!] {} => {} address matches",
        &source[..40.min(source.len())],
        matched.len()
    );

    let file_name = state.current_file.lock().unwrap().clone();

    if let Ok(conn) = Connection::open(&state.db_path) {
        for a in matched {
            let _ = conn.execute(
                "INSERT OR IGNORE INTO matches (address, source, file) VALUES (?1, ?2, ?3)",
                rusqlite::params![a.as_str(), source, file_name],
            );
        }
    }
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secs = now % 86400;
    let days = now / 86400;
    let y = 1970 + (days * 400 / 146097);
    format!(
        "{}-{:02}-{:02}T{:02}:{:02}:{:02}",
        y,
        (days % 365) / 30 + 1,
        (days % 365) % 30 + 1,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn api_status(state: Arc<AppState>) -> Json<Stats> {
    let count = state.counter.load(Ordering::Relaxed);
    let elapsed = state.start.elapsed().as_secs_f64();
    let speed = if elapsed > 0.0 {
        count as f64 / elapsed
    } else {
        0.0
    };
    Json(Stats {
        mode: state.mode,
        gpu_name: state.gpu_name.clone(),
        gpu_available: state.gpu_available,
        use_gpu: state.use_gpu.load(Ordering::Relaxed),
        status: state.status.lock().unwrap().clone(),
        running: state.running.load(Ordering::Relaxed),
        bench_running: state.bench_running.load(Ordering::Relaxed),
        total_mnemonics: count,
        total_hits: state.hits.load(Ordering::Relaxed),
        speed_mps: (speed * 10.0).round() / 10.0,
        elapsed_seconds: (elapsed * 10.0).round() / 10.0,
        utxo_set_size: state.utxo_size,
        threads: state.threads,
        depth: state.depth,
        paths: derive::PATHS_LABEL,
        paths_coverage: derive::PATHS_COVERAGE,
        addrs_per_mnemonic: derive::PATHS_COUNT * state.depth,
        current_file: state.current_file.lock().unwrap().clone(),
        pending_files: state.pending_files.load(Ordering::Relaxed) as usize,
        pending_by_dir: state.pending_by_dir.lock().unwrap().clone(),
    })
}

fn api_sysinfo(state: Arc<AppState>) -> Json<serde_json::Value> {
    let mut sys = state.sys.lock().unwrap();
    sys.refresh_cpu_usage();
    sys.refresh_memory();

    let cpu_usage: f32 = if sys.cpus().is_empty() {
        0.0
    } else {
        sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32
    };
    let used_mem_mb = sys.used_memory() / 1024 / 1024;

    let (gpu_util, gpu_mem_used, gpu_mem_total, gpu_temp) = get_gpu_stats();

    Json(serde_json::json!({
        "hostname": state.hostname,
        "cpu_name": state.cpu_name,
        "cpu_cores": sys.cpus().len(),
        "cpu_usage": (cpu_usage * 10.0).round() / 10.0,
        "mem_total_mb": state.total_memory_mb,
        "mem_used_mb": used_mem_mb,
        "gpu_name": state.gpu_name,
        "gpu_util": gpu_util,
        "gpu_mem_used_mb": gpu_mem_used,
        "gpu_mem_total_mb": gpu_mem_total,
        "gpu_temp_c": gpu_temp,
    }))
}

fn api_dir_stats(state: Arc<AppState>) -> Json<DirStatsMap> {
    Json(state.dir_stats.lock().unwrap().clone())
}

fn init_db(db_path: &PathBuf) {
    let conn = Connection::open(db_path).expect("Cannot open database");
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;").unwrap();
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS poc_progress (
            poc_id TEXT PRIMARY KEY,
            current_index INTEGER DEFAULT 0,
            batch_num INTEGER DEFAULT 0,
            total_generated INTEGER DEFAULT 0,
            total_space INTEGER DEFAULT 0,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS poc_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            poc_id TEXT NOT NULL,
            line TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE INDEX IF NOT EXISTS idx_poc_logs ON poc_logs(poc_id, id);
        CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT NOT NULL,
            source TEXT NOT NULL,
            file TEXT,
            found_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(address, source)
        );
        CREATE TABLE IF NOT EXISTS dir_stats (
            dir_label TEXT PRIMARY KEY,
            files_processed INTEGER DEFAULT 0,
            mnemonics_scanned INTEGER DEFAULT 0,
            privkeys_scanned INTEGER DEFAULT 0,
            hits INTEGER DEFAULT 0,
            last_file TEXT DEFAULT '',
            last_time TEXT DEFAULT ''
        );
    ").unwrap();
    let _ = conn.execute_batch(
        "ALTER TABLE dir_stats ADD COLUMN privkeys_scanned INTEGER DEFAULT 0;"
    );
    // Migrate matches table: change UNIQUE(address) to UNIQUE(address, source)
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS matches_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT NOT NULL,
            source TEXT NOT NULL,
            file TEXT,
            found_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(address, source)
        );
        INSERT OR IGNORE INTO matches_new (address, source, file, found_at)
            SELECT address, source, file, found_at FROM matches;
        DROP TABLE IF EXISTS matches;
        ALTER TABLE matches_new RENAME TO matches;"
    );
}

fn api_pocs_list(state: Arc<AppState>) -> Json<serde_json::Value> {
    let pocinfo_path = state.poc_base_dir.join("pocinfo.json");
    let pocs = if let Ok(content) = fs::read_to_string(&pocinfo_path) {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
            let mut groups = Vec::new();
            if let Some(vendors) = data.as_object() {
                for (_vendor_key, vendor_data) in vendors {
                    let product = vendor_data.get("product").and_then(|v| v.as_str()).unwrap_or(_vendor_key).to_string();
                    let vendor = vendor_data.get("vendor").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let mut poc_items = Vec::new();
                    let items: Vec<&serde_json::Value> = vendor_data.get("pocs").and_then(|p| p.as_array()).into_iter().flatten().collect();
                    for poc in items {
                        let id = poc.get("id")
                            .and_then(|v| v.as_str()).unwrap_or("");
                        let name = poc.get("name").or_else(|| poc.get("title"))
                            .and_then(|v| v.as_str()).unwrap_or("");
                        let versions = match poc.get("affected_versions") {
                            Some(v) if v.is_array() => v.clone(),
                            Some(v) if v.is_string() => serde_json::json!([v.as_str().unwrap_or("")]),
                            _ => serde_json::json!([]),
                        };
                        let has_generator = if !id.is_empty() {
                            state.poc_base_dir.join("targets").read_dir().ok()
                                .and_then(|dirs| {
                                    for d in dirs.filter_map(|e| e.ok()) {
                                        let gen = d.path().join(id).join("generator.py");
                                        if gen.is_file() { return Some(true); }
                                    }
                                    None
                                }).unwrap_or(false)
                        } else { false };
                        poc_items.push(serde_json::json!({
                            "id": id,
                            "name": name,
                            "output_type": poc.get("output_type").and_then(|v| v.as_str()).unwrap_or("unknown"),
                            "affected_versions": versions,
                            "severity": poc.get("severity").or(poc.get("risk_level")).and_then(|v| v.as_str()).unwrap_or(""),
                            "coverage_time_range": poc.get("coverage_time_range").and_then(|v| v.as_str()).unwrap_or(""),
                            "note": poc.get("note").and_then(|v| v.as_str()).unwrap_or(""),
                            "disclosure_status": poc.get("disclosure_status").and_then(|v| v.as_str()).unwrap_or(""),
                            "public": poc.get("public").and_then(|v| v.as_bool()).unwrap_or(false),
                            "is_fixed": poc.get("is_fixed").and_then(|v| v.as_bool()).unwrap_or(false),
                            "has_generator": has_generator,
                            "generation_speed": poc.get("generation_speed").and_then(|v| v.as_str()).unwrap_or(""),
                            "effective_entropy": poc.get("effective_entropy").or_else(|| poc.get("mathpoc").and_then(|m| m.get("effective_entropy"))).and_then(|v| v.as_str()).unwrap_or(""),
                            "input_space": poc.get("mathpoc").and_then(|m| m.get("input_space")).and_then(|v| v.as_str()).unwrap_or(""),
                            "root_cause": poc.get("vulnerability").and_then(|m| m.get("root_cause")).and_then(|v| v.as_str()).unwrap_or(""),
                            "source_reference": poc.get("source_reference").and_then(|v| v.as_str()).unwrap_or(""),
                            "vendor": &vendor,
                        }));
                    }
                    poc_items.sort_by(|a, b| {
                        let pa = a.get("public").and_then(|v| v.as_bool()).unwrap_or(false);
                        let pb = b.get("public").and_then(|v| v.as_bool()).unwrap_or(false);
                        pb.cmp(&pa)
                    });
                    groups.push(serde_json::json!({
                        "product": product,
                        "pocs": poc_items,
                    }));
                }
            }
            groups.sort_by(|a, b| {
                let has_pub = |g: &serde_json::Value| g.get("pocs").and_then(|v| v.as_array()).map(|arr| arr.iter().any(|p| p.get("public").and_then(|v| v.as_bool()).unwrap_or(false))).unwrap_or(false);
                let pa = has_pub(a);
                let pb = has_pub(b);
                pb.cmp(&pa)
            });
            serde_json::json!({"groups": groups})
        } else {
            serde_json::json!({"groups": [], "error": "parse error"})
        }
    } else {
        serde_json::json!({"groups": [], "error": "pocinfo.json not found"})
    };
    Json(pocs)
}

fn find_python_cmd() -> Vec<String> {
    // Windows uses py -3 -u
    let cmd_args: Vec<&str> = vec!["py", "-3", "-u"];
    let result = Command::new(cmd_args[0])
        .args(&cmd_args[1..])
        .arg("--version")
        .output();
    if let Ok(output) = result {
        if output.status.success() {
            return cmd_args.iter().map(|s| s.to_string()).collect();
        }
    }
    Vec::new()
}

fn insert_poc_log(db_path: &PathBuf, poc_id: &str, msg: &str) {
    if let Ok(conn) = Connection::open(db_path) {
        let _ = conn.execute(
            "INSERT INTO poc_logs (poc_id, line) VALUES (?1, ?2)",
            rusqlite::params![poc_id, msg],
        );
        let _ = conn.execute(
            "DELETE FROM poc_logs WHERE poc_id=?1 AND id NOT IN (SELECT id FROM poc_logs WHERE poc_id=?1 ORDER BY id DESC LIMIT 100)",
            rusqlite::params![poc_id],
        );
    }
}

fn api_pocs_start(state: Arc<AppState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let poc_id = parsed.get("poc_id").and_then(|v| v.as_str()).unwrap_or("").to_string();

    if poc_id.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "poc_id is empty"}));
    }

    let mgr = state.poc_manager.lock().unwrap();

    if mgr.processes.contains_key(&poc_id) {
        return Json(serde_json::json!({"ok": false, "error": "This POC is already running"}));
    }

    if mgr.active_count() >= mgr.max_concurrent {
        return Json(serde_json::json!({
            "ok": false,
            "error": format!("Concurrency limit {} reached, stop other POCs first", mgr.max_concurrent)
        }));
    }

    let maxfile_val = mgr.maxfile.to_string();
    drop(mgr);

    // Auto-backup database before start
    do_db_backup(&state.db_path);

    // Check if already 100% complete
    let force = parsed.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
    let progress = get_poc_progress(&poc_id, &state.db_path);
    if let Some(prog_obj) = progress.as_object() {
        let total_gen = prog_obj.get("total_generated").and_then(|v| v.as_u64()).unwrap_or(0);
        let total_space = prog_obj.get("total_space").and_then(|v| v.as_u64()).unwrap_or(0);
        if total_space > 0 && total_gen >= total_space {
            if !force {
                return Json(serde_json::json!({
                    "ok": false,
                    "completed": true,
                    "error": "This POC is 100% complete, running again will restart from 0%"
                }));
            }
            // force=true: reset progress
            let db_path = &state.db_path;
            if let Ok(conn) = Connection::open(&db_path) {
                let _ = conn.execute(
                    "INSERT INTO poc_progress (poc_id, current_index, batch_num, total_generated, total_space, updated_at) \
                     VALUES (?1, 0, 0, 0, ?2, datetime('now','localtime')) \
                     ON CONFLICT(poc_id) DO UPDATE SET current_index=0, batch_num=0, total_generated=0, total_space=?2, updated_at=datetime('now','localtime')",
                    rusqlite::params![poc_id, total_space as i64],
                );
            }
        }
    }

    let poc_script = state.poc_base_dir.join("main.py");
    if !poc_script.exists() {
        return Json(serde_json::json!({"ok": false, "error": format!("POC runner not found: {:?}", poc_script)}));
    }

    let output_dir = state.scanner_folder.join("waittocheck").join(&poc_id);
    let _ = fs::create_dir_all(&output_dir);
    let output_dir_str = output_dir.to_string_lossy().replace('\\', "/");

    // Windows: py -3, python; Linux/Mac: python3, python
    let python_cmd = find_python_cmd();
    if python_cmd.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "Python not found (tried py/python3/python)"}));
    }

    // Read resume position from progress table
    let (start_index, start_batch) = {
        let prog = get_poc_progress(&poc_id, &state.db_path);
        let idx = prog.get("index").and_then(|v| v.as_i64()).unwrap_or(0);
        let batch = prog.get("batch_num").and_then(|v| v.as_i64()).unwrap_or(0);
        (idx, batch)
    };

    // output_dir needs absolute path (because cwd switches to pocs/)
    let output_dir_abs = fs::canonicalize(&output_dir)
        .unwrap_or_else(|_| output_dir.clone())
        .to_string_lossy()
        .replace('\\', "/");

    let mut cmd = Command::new(&python_cmd[0]);
    for arg in &python_cmd[1..] {
        cmd.arg(arg);
    }
    cmd.env("PYTHONIOENCODING", "utf-8");
    cmd.env("PYTHONLEGACYWINDOWSSTDIO", "0");
    cmd.current_dir(&state.poc_base_dir);
    let child = cmd
        .arg("main.py")
        .arg("--poc")
        .arg(&poc_id)
        .arg("--output")
        .arg(&output_dir_abs)
        .arg("--maxfile")
        .arg(&maxfile_val)
        .arg("--start-index")
        .arg(start_index.to_string())
        .arg("--start-batch")
        .arg(start_batch.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    match child {
        Ok(mut child_proc) => {
            let stdout = child_proc.stdout.take().unwrap();
            let stderr = child_proc.stderr.take().unwrap();
            let poc_id_clone = poc_id.clone();
            let db_path_clone = state.db_path.clone();
            // stdout reader: parse structured output
            std::thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    let Ok(line) = line else { break };
                    if line.starts_with("##PROGRESS## ") {
                        let json_str = &line["##PROGRESS## ".len()..];
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) {
                            let idx = v.get("index").and_then(|x| x.as_i64()).unwrap_or(0);
                            let batch = v.get("batch_num").and_then(|x| x.as_i64()).unwrap_or(0);
                            let gen = v.get("total_generated").and_then(|x| x.as_i64()).unwrap_or(0);
                            let space = v.get("total_space").and_then(|x| x.as_i64()).unwrap_or(0);
                            if let Ok(conn) = Connection::open(&db_path_clone) {
                                let _ = conn.execute(
                                    "INSERT INTO poc_progress (poc_id, current_index, batch_num, total_generated, total_space, updated_at) \
                                     VALUES (?1, ?2, ?3, ?4, ?5, datetime('now','localtime')) \
                                     ON CONFLICT(poc_id) DO UPDATE SET current_index=?2, batch_num=?3, total_generated=?4, total_space=?5, updated_at=datetime('now','localtime')",
                                    rusqlite::params![poc_id_clone, idx, batch, gen, space],
                                );
                            }
                        }
                    } else if line.starts_with("##LOG## ") {
                        let msg = &line["##LOG## ".len()..];
                        insert_poc_log(&db_path_clone, &poc_id_clone, msg);
                    } else if !line.is_empty() {
                        insert_poc_log(&db_path_clone, &poc_id_clone, &line);
                    }
                }
            });
            // stderr reader: capture error messages to log
            let poc_id_clone2 = poc_id.clone();
            let db_path_clone2 = state.db_path.clone();
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    let Ok(line) = line else { break };
                    if !line.is_empty() {
                        insert_poc_log(&db_path_clone2, &poc_id_clone2, &format!("[stderr] {}", line));
                    }
                }
            });

            let poc_name = parsed.get("poc_name").and_then(|v| v.as_str()).unwrap_or(&poc_id).to_string();
            let mut mgr = state.poc_manager.lock().unwrap();
            mgr.processes.insert(poc_id.clone(), PocProcess {
                child: child_proc,
                poc_id: poc_id.clone(),
                poc_name,
                output_dir: output_dir_str,
                start_time: Instant::now(),
            });
            Json(serde_json::json!({"ok": true, "action": "started", "poc_id": poc_id}))
        }
        Err(e) => {
            Json(serde_json::json!({"ok": false, "error": format!("Failed to start: {}", e)}))
        }
    }
}

fn api_pocs_stop(state: Arc<AppState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let poc_id = parsed.get("poc_id").and_then(|v| v.as_str()).unwrap_or("").to_string();

    if poc_id.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "poc_id is empty"}));
    }

    let mut mgr = state.poc_manager.lock().unwrap();

    if let Some(mut proc) = mgr.processes.remove(&poc_id) {
        let _ = proc.child.kill();
        let _ = proc.child.wait();
        Json(serde_json::json!({"ok": true, "action": "stopped", "poc_id": poc_id}))
    } else {
        Json(serde_json::json!({"ok": false, "error": "This POC is not running"}))
    }
}

fn api_pocs_status(state: Arc<AppState>) -> Json<serde_json::Value> {
    let mut mgr = state.poc_manager.lock().unwrap();
    let mut statuses = Vec::new();
    let mut finished = Vec::new();

    for (id, proc) in mgr.processes.iter_mut() {
        match proc.child.try_wait() {
            Ok(Some(_status)) => {
                finished.push(id.clone());
                statuses.push(serde_json::json!({
                    "poc_id": proc.poc_id,
                    "poc_name": proc.poc_name,
                    "status": "finished",
                    "elapsed_secs": proc.start_time.elapsed().as_secs(),
                    "output_dir": proc.output_dir,
                    "progress": get_poc_progress(&proc.poc_id, &state.db_path),
                }));
            }
            Ok(None) => {
                statuses.push(serde_json::json!({
                    "poc_id": proc.poc_id,
                    "poc_name": proc.poc_name,
                    "status": "running",
                    "elapsed_secs": proc.start_time.elapsed().as_secs(),
                    "output_dir": proc.output_dir,
                    "progress": get_poc_progress(&proc.poc_id, &state.db_path),
                }));
            }
            Err(_) => {
                statuses.push(serde_json::json!({
                    "poc_id": proc.poc_id,
                    "poc_name": proc.poc_name,
                    "status": "error",
                    "elapsed_secs": proc.start_time.elapsed().as_secs(),
                    "output_dir": proc.output_dir,
                }));
            }
        }
    }

    for id in finished {
        mgr.processes.remove(&id);
    }

    let all_progress = get_all_poc_progress(&state.db_path);

    Json(serde_json::json!({
        "running_count": mgr.active_count(),
        "max_concurrent": mgr.max_concurrent,
        "maxfile": mgr.maxfile,
        "pocs": statuses,
        "all_progress": all_progress,
    }))
}

fn get_all_poc_progress(db_path: &PathBuf) -> serde_json::Value {
    if let Ok(conn) = Connection::open(db_path) {
        let mut map = serde_json::Map::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT poc_id, current_index, batch_num, total_generated, total_space, updated_at FROM poc_progress"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            }) {
                for row in rows.flatten() {
                    let (poc_id, idx, batch, generated, space, ts) = row;
                    map.insert(poc_id, serde_json::json!({
                        "index": idx,
                        "batch_num": batch,
                        "total_generated": generated,
                        "total_space": space,
                        "timestamp": ts,
                    }));
                }
            }
        }
        return serde_json::Value::Object(map);
    }
    serde_json::json!({})
}

fn get_poc_progress(poc_id: &str, db_path: &PathBuf) -> serde_json::Value {
    if let Ok(conn) = Connection::open(db_path) {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT current_index, batch_num, total_generated, total_space, updated_at FROM poc_progress WHERE poc_id=?"
        ) {
            if let Ok(row) = stmt.query_row([poc_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            }) {
                let (idx, batch, generated, space, ts) = row;
                return serde_json::json!({
                    "index": idx,
                    "batch_num": batch,
                    "total_generated": generated,
                    "total_space": space,
                    "timestamp": ts,
                });
            }
        }
    }
    serde_json::json!(null)
}

fn api_pocs_reload_info(state: Arc<AppState>) -> Json<serde_json::Value> {
    let reload_time = state.last_reload_time.lock().unwrap().clone();
    let reload_reason = state.reload_reason.lock().unwrap().clone();
    let mgr = state.poc_manager.lock().unwrap();
    Json(serde_json::json!({
        "last_reload_time": reload_time,
        "reload_reason": reload_reason,
        "running_count": mgr.active_count(),
    }))
}

fn api_pocs_log(state: Arc<AppState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let poc_id = parsed.get("poc_id").and_then(|v| v.as_str()).unwrap_or("");

    if poc_id.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "poc_id is empty"}));
    }

    let db_path = &state.db_path;
    let content = if let Ok(conn) = Connection::open(db_path) {
        let mut lines = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT line FROM poc_logs WHERE poc_id=? ORDER BY id DESC LIMIT 100"
        ) {
            if let Ok(rows) = stmt.query_map([poc_id], |row| row.get::<_, String>(0)) {
                for line in rows.flatten() {
                    lines.push(line);
                }
            }
        }
        lines.reverse();
        if lines.is_empty() {
            String::from("(no logs yet)")
        } else {
            lines.join("\n")
        }
    } else {
        String::from("(no logs yet)")
    };

    let is_running = {
        let mgr = state.poc_manager.lock().unwrap();
        mgr.processes.contains_key(poc_id)
    };

    Json(serde_json::json!({
        "ok": true,
        "poc_id": poc_id,
        "log": content,
        "is_running": is_running,
    }))
}

fn do_db_backup(db_path: &PathBuf) -> bool {
    let backup_path = db_path.with_extension("backup");
    if !db_path.exists() {
        return false;
    }
    if let Ok(src) = Connection::open(db_path) {
        if let Ok(mut dst) = Connection::open(&backup_path) {
            if let Ok(b) = rusqlite::backup::Backup::new(&src, &mut dst) {
                return b.run_to_completion(100, std::time::Duration::from_millis(10), None).is_ok();
            }
        }
    }
    false
}

fn api_pocs_backup(state: Arc<AppState>) -> Json<serde_json::Value> {
    if do_db_backup(&state.db_path) {
        let backup_path = state.db_path.with_extension("backup");
        Json(serde_json::json!({"ok": true, "backup": backup_path.to_string_lossy()}))
    } else {
        Json(serde_json::json!({"ok": false, "error": "Backup failed"}))
    }
}

fn api_pocs_edit_progress(state: Arc<AppState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let poc_id = parsed.get("poc_id").and_then(|v| v.as_str()).unwrap_or("");

    if poc_id.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "poc_id is empty"}));
    }

    {
        let mgr = state.poc_manager.lock().unwrap();
        if mgr.processes.contains_key(poc_id) {
            return Json(serde_json::json!({"ok": false, "error": "POC is running, please pause before editing progress"}));
        }
    }

    let current_index = parsed.get("current_index").and_then(|v| v.as_i64()).unwrap_or(-1);
    let batch_num = parsed.get("batch_num").and_then(|v| v.as_i64()).unwrap_or(-1);
    let total_generated = parsed.get("total_generated").and_then(|v| v.as_i64()).unwrap_or(-1);
    let total_space = parsed.get("total_space").and_then(|v| v.as_i64()).unwrap_or(-1);

    if current_index < 0 || total_space < 0 {
        return Json(serde_json::json!({"ok": false, "error": "current_index and total_space cannot be negative"}));
    }

    let db_path = &state.db_path;
    match Connection::open(db_path) {
        Ok(conn) => {
            let result = conn.execute(
                "INSERT INTO poc_progress (poc_id, current_index, batch_num, total_generated, total_space, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, datetime('now','localtime')) \
                 ON CONFLICT(poc_id) DO UPDATE SET current_index=?2, batch_num=?3, total_generated=?4, total_space=?5, updated_at=datetime('now','localtime')",
                rusqlite::params![poc_id, current_index, batch_num, total_generated, total_space],
            );
            match result {
                Ok(_) => Json(serde_json::json!({"ok": true})),
                Err(e) => Json(serde_json::json!({"ok": false, "error": format!("Save failed: {}", e)})),
            }
        }
        Err(e) => Json(serde_json::json!({"ok": false, "error": format!("Failed to open database: {}", e)})),
    }
}

fn api_pocs_reload(state: Arc<AppState>) -> Json<serde_json::Value> {
    let mgr = state.poc_manager.lock().unwrap();
    if mgr.active_count() > 0 {
        return Json(serde_json::json!({
            "ok": false,
            "error": format!("{} POCs are running, please pause all before reloading", mgr.active_count())
        }));
    }
    drop(mgr);

    *state.last_reload_time.lock().unwrap() = Some(chrono_now());
    *state.reload_reason.lock().unwrap() = Some("Manual reload".to_string());

    Json(serde_json::json!({"ok": true, "message": "Reload complete"}))
}

fn api_pocs_settings(state: Arc<AppState>, body: String) -> Json<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let mut mgr = state.poc_manager.lock().unwrap();

    if let Some(mc) = v.get("max_concurrent").and_then(|x| x.as_u64()) {
        if mc >= 1 && mc <= 50 {
            mgr.max_concurrent = mc as usize;
        }
    }

    if let Some(mf) = v.get("maxfile").and_then(|x| x.as_u64()) {
        if mgr.active_count() > 0 {
            return Json(serde_json::json!({
                "ok": false,
                "error": "Changing maxfile requires pausing all POCs",
                "max_concurrent": mgr.max_concurrent,
                "maxfile": mgr.maxfile
            }));
        }
        if mf >= 10 && mf <= 100000 {
            mgr.maxfile = mf as u32;
        }
    }

    Json(serde_json::json!({
        "ok": true,
        "max_concurrent": mgr.max_concurrent,
        "maxfile": mgr.maxfile
    }))
}

fn get_gpu_stats() -> (u32, u32, u32, u32) {
    let output = Command::new("nvidia-smi")
        .args(["--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu", "--format=csv,noheader,nounits"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout);
            let parts: Vec<&str> = s.trim().split(',').map(|p| p.trim()).collect();
            if parts.len() >= 4 {
                let util = parts[0].parse().unwrap_or(0);
                let mem_used = parts[1].parse().unwrap_or(0);
                let mem_total = parts[2].parse().unwrap_or(0);
                let temp = parts[3].parse().unwrap_or(0);
                (util, mem_used, mem_total, temp)
            } else {
                (0, 0, 0, 0)
            }
        }
        _ => (0, 0, 0, 0),
    }
}

fn api_results(state: Arc<AppState>) -> Json<serde_json::Value> {
    let mut results: Vec<serde_json::Value> = Vec::new();
    if let Ok(conn) = Connection::open(&state.db_path) {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT address, source, file, found_at FROM matches ORDER BY id DESC"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let source: String = row.get(1)?;
                let src_type = if source.len() == 64 && source.chars().all(|c| c.is_ascii_hexdigit()) {
                    "privkey"
                } else if (source.starts_with('5') || source.starts_with('K') || source.starts_with('L'))
                    && source.len() >= 51 && source.len() <= 52 {
                    "privkey"
                } else {
                    "mnemonic"
                };
                Ok(serde_json::json!({
                    "address": row.get::<_, String>(0)?,
                    "source": source,
                    "file": row.get::<_, Option<String>>(2)?,
                    "time": row.get::<_, Option<String>>(3)?,
                    "type": src_type,
                }))
            }) {
                for row in rows.flatten() {
                    results.push(row);
                }
            }
        }
    }
    Json(serde_json::json!({
        "count": results.len(),
        "results": results,
    }))
}

// Page serve handlers removed — Vue SPA handles all pages

#[derive(PartialEq)]
enum InputType {
    Mnemonic,
    Address,
    PrivateKey,
}


pub fn derive_from_private_key(key_str: &str) -> Result<Vec<(&'static str, String)>, String> {
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::key::{PublicKey, CompressedPublicKey};
    use bitcoin::{Address, Network};

    let key_bytes: [u8; 32] = if key_str.len() == 64 && key_str.as_bytes().iter().all(|&c| c.is_ascii_hexdigit()) {
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&key_str[i*2..i*2+2], 16)
                .map_err(|_| "Invalid hex private key".to_string())?;
        }
        bytes
    } else {
        let decoded = bs58::decode(key_str).into_vec()
            .map_err(|_| "WIF decode failed".to_string())?;
        if decoded.len() < 33 {
            return Err("WIF length too short".to_string());
        }
        let key_data = if decoded.len() == 38 {
            &decoded[1..33]
        } else if decoded.len() == 37 {
            &decoded[1..33]
        } else {
            return Err(format!("WIF unexpected length: {}", decoded.len()));
        };
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(key_data);
        bytes
    };

    let secret_key = SecretKey::from_slice(&key_bytes)
        .map_err(|e| format!("Invalid private key: {}", e))?;

    // Use thread_local Secp256k1 context to avoid ~256KB allocation per call
    derive::SECP.with(|secp| {
        let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(secp, &secret_key);
        let mut addrs = Vec::with_capacity(3);
        let pk = PublicKey::new(pubkey);
        addrs.push(("P2PKH (1...)", Address::p2pkh(pk, Network::Bitcoin).to_string()));
        let cpk = CompressedPublicKey(pubkey);
        addrs.push(("P2SH-P2WPKH (3...)", Address::p2shwpkh(&cpk, Network::Bitcoin).to_string()));
        addrs.push(("P2WPKH (bc1...)", Address::p2wpkh(&cpk, Network::Bitcoin).to_string()));
        Ok(addrs)
    })
}

fn api_convert(_state: Arc<AppState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let input_type = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("mnemonic");
    let content = parsed.get("content").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let depth: u32 = parsed.get("depth").and_then(|v| v.as_u64()).unwrap_or(3) as u32;

    if content.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "Content is empty"}));
    }

    match input_type {
        "mnemonic" => {
            match derive::derive_privkeys_from_mnemonic(&content, depth) {
                Ok(keys) => {
                    let items: Vec<serde_json::Value> = keys.iter().map(|k| {
                        serde_json::json!({
                            "path": k.path,
                            "privkey_wif": k.privkey_wif,
                            "privkey_hex": k.privkey_hex,
                            "address": k.address,
                        })
                    }).collect();
                    Json(serde_json::json!({"ok": true, "type": "mnemonic", "results": items}))
                }
                Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
            }
        }
        "privkey" => {
            match derive_from_private_key(&content) {
                Ok(addrs) => {
                    let items: Vec<serde_json::Value> = addrs.iter().map(|(label, addr)| {
                        serde_json::json!({"path": label, "address": addr})
                    }).collect();
                    Json(serde_json::json!({"ok": true, "type": "privkey", "results": items}))
                }
                Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
            }
        }
        _ => Json(serde_json::json!({"ok": false, "error": "Unknown type, supports mnemonic / privkey"})),
    }
}

fn run_bench(state: Arc<AppState>, content: String, type_str: &str) {
    let depth = state.depth;
    let lines: Vec<String> = content.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let bench_log = |msg: String| {
        state.bench_log.lock().unwrap().push(msg);
    };

    if lines.is_empty() {
        bench_log("Input is empty".to_string());
        state.bench_done.store(true, Ordering::Relaxed);
        state.bench_running.store(false, Ordering::Relaxed);
        return;
    }

    let input_type = match type_str {
        "address" => InputType::Address,
        "privkey" => InputType::PrivateKey,
        _ => InputType::Mnemonic,
    };
    bench_log(format!("=== Benchmark ==="));
    bench_log(format!("Input lines: {}", lines.len()));
    bench_log(format!("Type: {}", match input_type {
        InputType::Address => "Address (direct UTXO query)",
        InputType::PrivateKey => "Private Key (derive address then query)",
        InputType::Mnemonic => "Mnemonic (derive address then query)",
    }));
    bench_log(format!("UTXO set: {} addresses", state.utxo_size));
    bench_log(format!(""));

    let start = Instant::now();
    let mut total_hits = 0usize;

    match input_type {
        InputType::Address => {
            for (i, addr) in lines.iter().enumerate() {
                let matched = state.utxo_set.contains(addr);
                let mark = if matched { " <<< HIT >>>" } else { "" };
                bench_log(format!("[{}/{}] {}{}", i + 1, lines.len(), addr, mark));
                if matched { total_hits += 1; }
            }
        }
        InputType::PrivateKey => {
            for (i, key_str) in lines.iter().enumerate() {
                bench_log(format!("[{}/{}] \"{}\"", i + 1, lines.len(), key_str));
                match derive_from_private_key(key_str) {
                    Ok(addrs) => {
                        for (label, addr) in &addrs {
                            let matched = state.utxo_set.contains(addr);
                            let mark = if matched { " <<< HIT >>>" } else { "" };
                            bench_log(format!("  {}: {}{}", label, addr, mark));
                            if matched { total_hits += 1; }
                        }
                    }
                    Err(e) => {
                        bench_log(format!("  [Error] {}", e));
                    }
                }
                bench_log(format!(""));
            }
        }
        InputType::Mnemonic => {
            let use_gpu = state.gpu.is_some() && state.use_gpu.load(Ordering::Relaxed);
            bench_log(format!("Mode: {}", if use_gpu { "CUDA (GPU PBKDF2 + CPU derive)" } else { "Rayon (CPU)" }));
            bench_log(format!("Strategy: {} ({})", derive::PATHS_LABEL, derive::PATHS_COVERAGE));
            bench_log(format!("Depth: {} (index 0~{})", depth, depth - 1));
            bench_log(format!("Addresses per mnemonic: {}", derive::PATHS_COUNT * depth));
            bench_log(format!(""));

            let paths = ["m/44'/0'/0'/0", "m/49'/0'/0'/0", "m/84'/0'/0'/0"];
            let path_names = ["P2PKH (1...)", "P2SH-P2WPKH (3...)", "P2WPKH (bc1...)"];

            if use_gpu {
                let batch_size = state.gpu.as_ref().unwrap().lock().unwrap().max_batch_size() as usize;
                let mut use_b = false;

                for chunk in lines.chunks(batch_size) {
                    let seeds = {
                        let acc = state.gpu.as_ref().unwrap().lock().unwrap();
                        match acc.pbkdf2_batch(chunk, use_b) {
                            Ok(s) => s,
                            Err(e) => {
                                bench_log(format!("[GPU PBKDF2 failed: {}, falling back to CPU]", e));
                                for m in chunk.iter() {
                                    let idx = lines.iter().position(|x| x == m).unwrap_or(0) + 1;
                                    bench_log(format!("[{}/{}] \"{}\"", idx, lines.len(), m));
                                    let addrs = derive::derive_addresses(m, depth);
                                    let mut addr_idx = 0;
                                    for (p, path) in paths.iter().enumerate() {
                                        bench_log(format!("  {} [{}]:", path, path_names[p]));
                                        for child in 0..depth {
                                            if addr_idx < addrs.len() {
                                                let addr = &addrs[addr_idx];
                                                let matched = state.utxo_set.contains(addr);
                                                let mark = if matched { " <<< HIT >>>" } else { "" };
                                                bench_log(format!("    /{}: {}{}", child, addr, mark));
                                                if matched { total_hits += 1; }
                                            }
                                            addr_idx += 1;
                                        }
                                    }
                                    bench_log(format!(""));
                                }
                                continue;
                            }
                        }
                    };
                    use_b = !use_b;

                    for (i, seed) in seeds.iter().enumerate() {
                        let mnemonic = &chunk[i];
                        let idx = lines.iter().position(|m| m == mnemonic).unwrap_or(0) + 1;
                        bench_log(format!("[{}/{}] \"{}\"", idx, lines.len(), mnemonic));
                        let addrs = derive::derive_from_seed(seed, depth);
                        let mut addr_idx = 0;
                        for (p, path) in paths.iter().enumerate() {
                            bench_log(format!("  {} [{}]:", path, path_names[p]));
                            for child in 0..depth {
                                if addr_idx < addrs.len() {
                                    let addr = &addrs[addr_idx];
                                    let matched = state.utxo_set.contains(addr);
                                    let mark = if matched { " <<< HIT >>>" } else { "" };
                                    bench_log(format!("    /{}: {}{}", child, addr, mark));
                                    if matched { total_hits += 1; }
                                }
                                addr_idx += 1;
                            }
                        }
                        bench_log(format!(""));
                    }
                }
            } else {
                for (i, mnemonic) in lines.iter().enumerate() {
                    bench_log(format!("[{}/{}] \"{}\"", i + 1, lines.len(), mnemonic));
                    let addrs = derive::derive_addresses(mnemonic, depth);
                    let mut addr_idx = 0;
                    for (p, path) in paths.iter().enumerate() {
                        bench_log(format!("  {} [{}]:", path, path_names[p]));
                        for child in 0..depth {
                            if addr_idx < addrs.len() {
                                let addr = &addrs[addr_idx];
                                let matched = state.utxo_set.contains(addr);
                                let mark = if matched { " <<< HIT >>>" } else { "" };
                                bench_log(format!("    /{}: {}{}", child, addr, mark));
                                if matched { total_hits += 1; }
                            }
                            addr_idx += 1;
                        }
                    }
                    bench_log(format!(""));
                }
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    bench_log(format!("=== Results ==="));
    bench_log(format!("Elapsed: {:.2}s", elapsed));
    bench_log(format!("Hits: {}", total_hits));

    state.bench_running.store(false, Ordering::Relaxed);
    state.bench_done.store(true, Ordering::Relaxed);
}


// HTML page constants removed — Vue SPA in webui/ handles all pages
