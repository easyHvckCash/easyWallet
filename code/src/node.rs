use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use reqwest::Client;
use rusqlite::Connection;
use sysinfo::System;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::{Duration, sleep};

use crate::protocol::*;
use crate::Args;

fn generate_machine_id() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let raw = get_machine_raw_id();
    let mut hasher = DefaultHasher::new();
    raw.hash(&mut hasher);
    let hash = hasher.finish();
    format!("{:016x}", hash)
}

fn get_machine_raw_id() -> String {
    // Linux: /etc/machine-id
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        let id = id.trim().to_string();
        if !id.is_empty() { return id; }
    }
    // macOS: IOPlatformUUID via ioreg
    if let Ok(output) = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("IOPlatformUUID") {
                if let Some(uuid) = line.split('"').nth(3) {
                    return uuid.to_string();
                }
            }
        }
    }
    // Windows: wmic or reg query for MachineGuid
    if let Ok(output) = std::process::Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("MachineGuid") {
                if let Some(guid) = line.split_whitespace().last() {
                    return guid.to_string();
                }
            }
        }
    }
    // Fallback: hostname
    System::host_name().unwrap_or_else(|| "unknown-host".to_string())
}

pub struct NodeState {
    pub node_id: TokioMutex<Option<String>>,
    pub server_url: String,
    pub token: String,
    pub client: Client,
    pub speed: AtomicU64,  // stored as bits of f64
    pub total_scanned: AtomicU64,
    pub total_hits: AtomicU64,
    pub start: Instant,
    pub cache_db: std::sync::Mutex<Connection>,
    pub folder: PathBuf,
    pub depth: u32,
    pub threads: usize,
    pub benchmark_speed: f64,
    pub current_task_id: TokioMutex<Option<String>>,
    pub cancel_requested: AtomicBool,
    pub gpu_available: bool,
    pub gpu_error: String,
    pub compute_mode: std::sync::Mutex<String>, // "gpu" or "cpu"
    pub pending_mode_switch: std::sync::Mutex<Option<String>>, // requested by master
    pub utxo_filter: Option<Arc<crate::UtxoFilter>>,
}
fn init_local_cache(folder: &PathBuf) -> Connection {
    let db_path = folder.join("local_cache.db");
    let conn = Connection::open(&db_path).expect("Failed to open local_cache.db");
    conn.execute_batch("
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        CREATE TABLE IF NOT EXISTS hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT,
            poc_id TEXT DEFAULT '',
            source TEXT,
            address TEXT,
            discovered_at TEXT,
            reported INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS task_results (
            task_id TEXT PRIMARY KEY,
            node_id TEXT,
            poc_id TEXT DEFAULT '',
            scanned_count INTEGER,
            hit_count INTEGER,
            completed_at TEXT,
            reported INTEGER DEFAULT 0
        );
    ").expect("Failed to init local cache schema");
    // Schema migration: add poc_id columns if missing (for existing DBs)
    let _ = conn.execute("ALTER TABLE hits ADD COLUMN poc_id TEXT DEFAULT ''", []);
    let _ = conn.execute("ALTER TABLE task_results ADD COLUMN poc_id TEXT DEFAULT ''", []);
    conn
}
pub async fn run_node(args: Args) {
    let server = args.server.as_ref().expect("--server required for node role");
    let server_url = if server.starts_with("http") {
        server.clone()
    } else {
        format!("http://{}", server)
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("Failed to create HTTP client");

    // Step 1: Verify master is reachable
    println!("[Node] Checking master at {}...", server_url);
    loop {
        match client.get(format!("{}/api/cluster/status", server_url))
            .header("Authorization", format!("Bearer {}", args.token))
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                println!("[Node] Master is reachable");
                break;
            }
            Ok(resp) => {
                println!("[Node] Master responded {}, retrying in 3s...", resp.status());
            }
            Err(e) => {
                println!("[Node] Cannot reach master: {}, retrying in 3s...", e);
            }
        }
        sleep(Duration::from_secs(3)).await;
    }

    // Step 2: Load UTXO filter + GPU self-check
    println!("[Node] Loading UTXO filter...");
    let utxo_set = crate::load_utxo_filter(&args.folder);
    println!("[Node] UTXO filter loaded");

    println!("[Node] Detecting compute capabilities...");
    let (gpu, gpu_available, gpu_error) = init_gpu_with_diagnostics(&utxo_set);
    let initial_mode = if gpu_available { "gpu" } else { "cpu" };
    if gpu_available {
        println!("[Node] GPU available, compute mode: GPU");
    } else {
        println!("[Node] GPU not available ({}), compute mode: CPU", gpu_error);
    }

    // Step 3: Benchmark using real scan pipeline (100K mnemonics)
    println!("[Node] Running benchmark (100K mnemonics, real pipeline)...");
    let benchmark_speed = run_benchmark(&args, &utxo_set, &gpu);
    println!("[Node] Benchmark: {:.0} mnemonic/s", benchmark_speed);

    // Step 4: Build state and register
    let cache_db = init_local_cache(&args.folder);
    let machine_node_id = generate_machine_id();
    println!("[Node] Machine ID: {}", &machine_node_id[..machine_node_id.len().min(8)]);

    let state = Arc::new(NodeState {
        node_id: TokioMutex::new(Some(machine_node_id.clone())),
        server_url,
        token: args.token.clone(),
        client,
        speed: AtomicU64::new(benchmark_speed.to_bits()),
        total_scanned: AtomicU64::new(0),
        total_hits: AtomicU64::new(0),
        start: Instant::now(),
        cache_db: std::sync::Mutex::new(cache_db),
        folder: args.folder.clone(),
        depth: args.depth,
        threads: args.threads,
        benchmark_speed,
        current_task_id: TokioMutex::new(None),
        cancel_requested: AtomicBool::new(false),
        gpu_available,
        gpu_error: gpu_error.clone(),
        compute_mode: std::sync::Mutex::new(initial_mode.to_string()),
        pending_mode_switch: std::sync::Mutex::new(None),
        utxo_filter: Some(utxo_set.clone()),
    });

    register_with_master(&state).await;

    // Step 5: Start background threads and main loop
    let retry_state = state.clone();
    tokio::spawn(async move { report_retry_loop(retry_state).await });

    let hb_state = state.clone();
    tokio::spawn(async move { heartbeat_loop(hb_state).await });

    task_pull_loop_with_resources(state, utxo_set, gpu).await;
}

fn init_gpu_with_diagnostics(
    utxo_set: &std::sync::Arc<crate::UtxoFilter>,
) -> (Option<std::sync::Mutex<crate::cuda::GpuAccelerator>>, bool, String) {
    // Use the existing init function which handles all the CUDA setup
    match crate::try_init_gpu_with_filter(utxo_set) {
        Some(gpu) => (Some(gpu), true, String::new()),
        None => {
            // Determine the reason
            let cuda_ctx = crate::cuda::CudaDetect::init();
            let error = if !cuda_ctx.is_available() {
                "CUDA runtime not available".to_string()
            } else if !crate::cuda::kernel_ready() {
                "CUDA kernel not found or incompatible".to_string()
            } else {
                "GPU accelerator initialization failed".to_string()
            };
            (None, false, error)
        }
    }
}

fn run_benchmark(
    args: &Args,
    utxo_set: &Arc<crate::UtxoFilter>,
    gpu: &Option<std::sync::Mutex<crate::cuda::GpuAccelerator>>,
) -> f64 {
    const BENCH_COUNT: usize = 100_000;

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
    let batch: Vec<String> = vec![mnemonic; BENCH_COUNT];

    let start = Instant::now();
    // Use the exact same scan path as real tasks
    let _ = crate::scan_mnemonics_batch(&batch, args.depth, utxo_set, gpu);
    let elapsed = start.elapsed().as_secs_f64();

    if elapsed > 0.0 {
        BENCH_COUNT as f64 / elapsed
    } else {
        1000.0
    }
}
async fn register_with_master(state: &Arc<NodeState>) {
    let mut sys = System::new_all();
    sys.refresh_all();

    let gpu_name = detect_gpu_name();
    let cpu_name = sys.cpus().first()
        .map(|c| c.brand().to_string())
        .unwrap_or_else(|| "Unknown CPU".to_string());
    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let total_memory_mb = sys.total_memory() / 1024 / 1024;

    let node_id = state.node_id.lock().await.clone().unwrap_or_default();
    let current_mode = state.compute_mode.lock().unwrap().clone();
    let req = RegisterRequest {
        node_id: node_id.clone(),
        gpu_name: gpu_name.clone(),
        cpu_name,
        hostname: hostname.clone(),
        total_memory_mb,
        benchmark_speed: state.benchmark_speed,
        gpu_available: state.gpu_available,
        gpu_error: state.gpu_error.clone(),
        compute_mode: current_mode,
    };

    loop {
        match state.client.post(format!("{}/api/node/register", state.server_url))
            .header("Authorization", format!("Bearer {}", state.token))
            .json(&req)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if status.as_u16() == 409 {
                    println!("[Node] CONFLICT: Another instance with the same machine ID is already connected to this master.");
                    println!("[Node] Only one process per machine is allowed. Exiting.");
                    std::process::exit(1);
                }
                match resp.text().await {
                    Ok(text) => {
                        match serde_json::from_str::<serde_json::Value>(&text) {
                            Ok(body) => {
                                if body.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                                    println!("[Node] Registered as {} ({})", &node_id[..node_id.len().min(8)], gpu_name);
                                    return;
                                }
                                println!("[Node] Registration failed (status={}): {}", status, text);
                            }
                            Err(e) => {
                                println!("[Node] Registration failed: invalid JSON (status={}): {} | body: {}", status, e, text);
                            }
                        }
                    }
                    Err(e) => {
                        println!("[Node] Registration failed: cannot read body (status={}): {}", status, e);
                    }
                }
            }
            Err(e) => {
                println!("[Node] Cannot reach master: {}", e);
            }
        }
        sleep(Duration::from_secs(3)).await;
    }
}

fn detect_gpu_name() -> String {
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("nvidia-smi")
            .args(["--query-gpu=name", "--format=csv,noheader"])
            .output()
        {
            if output.status.success() {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !name.is_empty() { return name; }
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(output) = std::process::Command::new("nvidia-smi")
            .args(["--query-gpu=name", "--format=csv,noheader"])
            .output()
        {
            if output.status.success() {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !name.is_empty() { return name; }
            }
        }
    }
    "CPU-only".to_string()
}

struct GpuStats {
    utilization: f32,
    mem_used_mb: u64,
    mem_total_mb: u64,
    temp_c: u32,
}

fn query_gpu_stats() -> GpuStats {
    let default = GpuStats { utilization: 0.0, mem_used_mb: 0, mem_total_mb: 0, temp_c: 0 };
    let output = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu", "--format=csv,noheader,nounits"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout);
            let parts: Vec<&str> = s.trim().split(',').map(|p| p.trim()).collect();
            if parts.len() >= 4 {
                GpuStats {
                    utilization: parts[0].parse().unwrap_or(0.0),
                    mem_used_mb: parts[1].parse().unwrap_or(0),
                    mem_total_mb: parts[2].parse().unwrap_or(0),
                    temp_c: parts[3].parse().unwrap_or(0),
                }
            } else { default }
        }
        _ => default,
    }
}

async fn heartbeat_loop(state: Arc<NodeState>) {
    let mut sys = System::new();
    loop {
        sleep(Duration::from_secs(5)).await;
        sys.refresh_cpu_usage();
        sys.refresh_memory();

        let node_id = match state.node_id.lock().await.clone() {
            Some(id) => id,
            None => continue,
        };

        let speed_bits = state.speed.load(Ordering::Relaxed);
        let speed = f64::from_bits(speed_bits);

        let current_task = state.current_task_id.lock().await.clone();

        let cpu_pct = sys.global_cpu_usage() as f64;
        let mem_pct = if sys.total_memory() > 0 {
            (sys.used_memory() as f64 / sys.total_memory() as f64) * 100.0
        } else { 0.0 };
        let gpu = query_gpu_stats();
        let current_mode = state.compute_mode.lock().unwrap().clone();
        let req = HeartbeatRequest {
            node_id,
            speed,
            total_scanned: state.total_scanned.load(Ordering::Relaxed),
            total_hits: state.total_hits.load(Ordering::Relaxed),
            gpu_utilization: gpu.utilization,
            current_task_id: current_task.clone(),
            cpu_usage: cpu_pct,
            memory_usage: mem_pct,
            gpu_memory_used_mb: gpu.mem_used_mb,
            gpu_memory_total_mb: gpu.mem_total_mb,
            gpu_temp_c: gpu.temp_c,
            compute_mode: current_mode,
        };

        match state.client.post(format!("{}/api/node/heartbeat", state.server_url))
            .header("Authorization", format!("Bearer {}", state.token))
            .json(&req)
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    // Check for cancel commands
                    if let Some(cancels) = body.get("cancel_tasks").and_then(|v| v.as_array()) {
                        if let Some(ref cur) = current_task {
                            for c in cancels {
                                if let Some(tid) = c.as_str() {
                                    if tid == cur {
                                        println!("[Node] Cancel requested for task {}", &tid[..8]);
                                        state.cancel_requested.store(true, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    }
                    // Check for compute mode switch command
                    if let Some(new_mode) = body.get("switch_compute_mode").and_then(|v| v.as_str()) {
                        if !new_mode.is_empty() {
                            *state.pending_mode_switch.lock().unwrap() = Some(new_mode.to_string());
                        }
                    }
                    // Check for bench task
                    if let Some(bench_val) = body.get("bench_task") {
                        if !bench_val.is_null() {
                            if let Ok(bench_task) = serde_json::from_value::<crate::protocol::BenchTask>(bench_val.clone()) {
                                let s = state.clone();
                                tokio::spawn(async move {
                                    execute_bench_task(s, bench_task).await;
                                });
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
}

async fn execute_bench_task(state: Arc<NodeState>, task: crate::protocol::BenchTask) {
    println!("[Node] Received bench task {}, executing...", task.bench_id);
    let utxo = state.utxo_filter.clone();
    let depth = task.depth;
    let input_type = task.input_type.clone();
    let lines = task.lines.clone();
    let bench_id = task.bench_id.clone();
    let node_id = state.node_id.lock().await.clone().unwrap_or_default();

    let results = tokio::task::spawn_blocking(move || {
        let mut out: Vec<crate::protocol::BenchResultLine> = Vec::new();
        for line in &lines {
            let derived = match input_type.as_str() {
                "mnemonic" => {
                    match crate::derive::derive_privkeys_from_mnemonic(line, depth) {
                        Ok(keys) => keys.iter().map(|k| {
                            let hit = utxo.as_ref().map(|u| u.contains(&k.address)).unwrap_or(false);
                            crate::protocol::BenchDerived { path: k.path.clone(), address: k.address.clone(), hit }
                        }).collect(),
                        Err(_) => vec![],
                    }
                }
                "privkey" => {
                    match crate::derive_from_private_key(line) {
                        Ok(addrs) => addrs.iter().map(|(label, addr)| {
                            let hit = utxo.as_ref().map(|u| u.contains(addr.as_str())).unwrap_or(false);
                            crate::protocol::BenchDerived { path: label.to_string(), address: addr.clone(), hit }
                        }).collect(),
                        Err(_) => vec![],
                    }
                }
                "address" => {
                    let hit = utxo.as_ref().map(|u| u.contains(line)).unwrap_or(false);
                    vec![crate::protocol::BenchDerived { path: "direct".to_string(), address: line.clone(), hit }]
                }
                _ => vec![],
            };
            out.push(crate::protocol::BenchResultLine { input: line.clone(), derived });
        }
        out
    }).await.unwrap_or_default();

    let req = crate::protocol::BenchResultRequest { node_id, bench_id: bench_id.clone(), results };
    match state.client.post(format!("{}/api/bench/result", state.server_url))
        .header("Authorization", format!("Bearer {}", state.token))
        .json(&req)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            println!("[Node] Bench {} results sent to master", bench_id);
        }
        Ok(resp) => {
            println!("[Node] Bench {} result submission failed: {}", bench_id, resp.status());
        }
        Err(e) => {
            println!("[Node] Bench {} result submission error: {}", bench_id, e);
        }
    }
}

async fn task_pull_loop_with_resources(
    state: Arc<NodeState>,
    utxo_set: Arc<crate::UtxoFilter>,
    gpu: Option<std::sync::Mutex<crate::cuda::GpuAccelerator>>,
) {
    println!("[Node] Ready, pulling tasks...");

    loop {
        // Check for pending mode switch (only between tasks = idle)
        if let Some(new_mode) = state.pending_mode_switch.lock().unwrap().take() {
            let current = state.compute_mode.lock().unwrap().clone();
            if new_mode != current {
                if new_mode == "gpu" && !state.gpu_available {
                    println!("[Node] Cannot switch to GPU: {}", state.gpu_error);
                } else {
                    *state.compute_mode.lock().unwrap() = new_mode.clone();
                    println!("[Node] Compute mode switched to: {}", new_mode.to_uppercase());
                }
            }
        }

        let node_id = match state.node_id.lock().await.clone() {
            Some(id) => id,
            None => { sleep(Duration::from_secs(1)).await; continue; }
        };

        let pull_req = TaskPullRequest {
            node_id: node_id.clone(),
            preferred_batch_size: None,
        };

        let resp = state.client.post(format!("{}/api/task/pull", state.server_url))
            .header("Authorization", format!("Bearer {}", state.token))
            .json(&pull_req)
            .timeout(Duration::from_secs(35))
            .send()
            .await;

        match resp {
            Ok(r) => {
                if let Ok(body) = r.json::<serde_json::Value>().await {
                    if let Some(task_val) = body.get("task") {
                        if !task_val.is_null() {
                            if let Ok(task) = serde_json::from_value::<TaskPayload>(task_val.clone()) {
                                // Set current task and reset cancel flag
                                *state.current_task_id.lock().await = Some(task.task_id.clone());
                                state.cancel_requested.store(false, Ordering::Relaxed);

                                let scan_start = Instant::now();
                                let use_gpu = state.compute_mode.lock().unwrap().clone() == "gpu";
                                let no_gpu: Option<std::sync::Mutex<crate::cuda::GpuAccelerator>> = None;
                                let effective_gpu = if use_gpu { &gpu } else { &no_gpu };
                                let hits = scan_task(&state, &task, &utxo_set, effective_gpu).await;
                                let elapsed = scan_start.elapsed().as_secs_f64();
                                let count = task.batch.len() as u64;

                                // Clear current task
                                *state.current_task_id.lock().await = None;

                                // If cancelled, don't report (master already re-queued)
                                if state.cancel_requested.load(Ordering::Relaxed) {
                                    println!("[Node] Task {} cancelled, discarding partial results", &task.task_id[..8]);
                                    continue;
                                }

                                // Update speed
                                let speed = if elapsed > 0.0 { count as f64 / elapsed } else { 0.0 };
                                state.speed.store(speed.to_bits(), Ordering::Relaxed);
                                state.total_scanned.fetch_add(count, Ordering::Relaxed);
                                state.total_hits.fetch_add(hits.len() as u64, Ordering::Relaxed);

                                // IMMEDIATE: report hits to master right away if any
                                if !hits.is_empty() {
                                    println!("[Node] {} HIT(s) found! Reporting immediately...", hits.len());
                                    report_hits_immediate(&state, &node_id, &task.task_id, &task.poc_id, &hits).await;
                                }

                                // Cache result locally
                                cache_result(&state, &node_id, &task.task_id, &task.poc_id, count, &hits);

                                // Report task completion (hits already sent via immediate report)
                                let empty_hits: Vec<HitRecord> = vec![];
                                report_single_result(&state, &node_id, &task.task_id, &task.poc_id, count, &empty_hits).await;

                                continue;
                            }
                        }
                    }
                }
                // No task available, will long-poll again
            }
            Err(e) => {
                println!("[Node] Pull failed: {}, retrying in 5s", e);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}
async fn scan_task(
    state: &Arc<NodeState>,
    task: &TaskPayload,
    utxo_set: &Arc<crate::UtxoFilter>,
    gpu: &Option<std::sync::Mutex<crate::cuda::GpuAccelerator>>,
) -> Vec<HitRecord> {
    let mut hits = Vec::new();
    let depth = task.depth;

    match task.task_type.as_str() {
        "mnemonic" => {
            let results = crate::scan_mnemonics_batch(&task.batch, depth, utxo_set, gpu);
            for (mnemonic, address) in results {
                let hit = HitRecord {
                    source: mnemonic,
                    address,
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                };
                // Immediately persist hit locally
                cache_hit(state, &task.task_id, &task.poc_id, &hit);
                hits.push(hit);
            }
        }
        "privkey" => {
            let results = crate::scan_privkeys_batch(&task.batch, utxo_set);
            for (privkey, address) in results {
                let hit = HitRecord {
                    source: privkey,
                    address,
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                };
                cache_hit(state, &task.task_id, &task.poc_id, &hit);
                hits.push(hit);
            }
        }
        _ => {}
    }

    hits
}

fn cache_hit(state: &Arc<NodeState>, task_id: &str, poc_id: &str, hit: &HitRecord) {
    if let Ok(db) = state.cache_db.lock() {
        let _ = db.execute(
            "INSERT INTO hits (task_id, poc_id, source, address, discovered_at, reported) VALUES (?1,?2,?3,?4,?5,0)",
            rusqlite::params![task_id, poc_id, hit.source, hit.address, hit.discovered_at],
        );
    }
}

fn cache_result(state: &Arc<NodeState>, node_id: &str, task_id: &str, poc_id: &str, scanned: u64, hits: &[HitRecord]) {
    if let Ok(db) = state.cache_db.lock() {
        let _ = db.execute(
            "INSERT OR REPLACE INTO task_results (task_id, node_id, poc_id, scanned_count, hit_count, completed_at, reported) VALUES (?1,?2,?3,?4,?5,datetime('now'),0)",
            rusqlite::params![task_id, node_id, poc_id, scanned, hits.len()],
        );
    }
}
async fn report_hits_immediate(state: &Arc<NodeState>, node_id: &str, task_id: &str, poc_id: &str, hits: &[HitRecord]) {
    let payload = serde_json::json!({
        "node_id": node_id,
        "task_id": task_id,
        "poc_id": poc_id,
        "hits": hits,
    });
    let _ = state.client.post(format!("{}/api/task/hits", state.server_url))
        .header("Authorization", format!("Bearer {}", state.token))
        .json(&payload)
        .send()
        .await;
}
async fn report_single_result(state: &Arc<NodeState>, node_id: &str, task_id: &str, poc_id: &str, scanned: u64, hits: &[HitRecord]) {
    let req = TaskResultRequest {
        node_id: node_id.to_string(),
        task_id: task_id.to_string(),
        poc_id: poc_id.to_string(),
        scanned_count: scanned,
        hits: hits.to_vec(),
    };

    match state.client.post(format!("{}/api/task/result", state.server_url))
        .header("Authorization", format!("Bearer {}", state.token))
        .json(&req)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if body.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                        mark_reported(state, task_id);
                        return;
                    }
                }
            }
            // Server did not confirm, keep locally for retry
            println!("[Node] Result for {} not confirmed, will retry", &task_id[..8]);
        }
        Err(_) => {
            // Network failure, will be retried by report_retry_loop
        }
    }
}

fn mark_reported(state: &Arc<NodeState>, task_id: &str) {
    if let Ok(db) = state.cache_db.lock() {
        let _ = db.execute("UPDATE task_results SET reported=1 WHERE task_id=?1", rusqlite::params![task_id]);
        let _ = db.execute("UPDATE hits SET reported=1 WHERE task_id=?1", rusqlite::params![task_id]);
    }
}

async fn report_retry_loop(state: Arc<NodeState>) {
    // Wait for registration
    loop {
        if state.node_id.lock().await.is_some() { break; }
        sleep(Duration::from_secs(1)).await;
    }

    loop {
        sleep(Duration::from_secs(2)).await;

        let node_id = match state.node_id.lock().await.clone() {
            Some(id) => id,
            None => continue,
        };

        // Find unreported task results
        let unreported = {
            let db = match state.cache_db.lock() {
                Ok(db) => db,
                Err(_) => continue,
            };
            let mut stmt = match db.prepare(
                "SELECT task_id, scanned_count, hit_count, COALESCE(poc_id,'') FROM task_results WHERE reported=0 LIMIT 10"
            ) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let rows: Vec<(String, u64, u64, String)> = stmt.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            }).ok().map(|r| r.flatten().collect()).unwrap_or_default();
            rows
        };

        for (task_id, scanned_count, _hit_count, cached_poc_id) in &unreported {
            // Gather ALL unreported hits for this task
            let hits = {
                let db = match state.cache_db.lock() {
                    Ok(db) => db,
                    Err(_) => continue,
                };
                let mut stmt = match db.prepare(
                    "SELECT source, address, discovered_at FROM hits WHERE task_id=?1 AND reported=0"
                ) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let rows: Vec<HitRecord> = stmt.query_map(rusqlite::params![task_id], |row| {
                    Ok(HitRecord {
                        source: row.get(0)?,
                        address: row.get(1)?,
                        discovered_at: row.get(2)?,
                    })
                }).ok().map(|r| r.flatten().collect()).unwrap_or_default();
                rows
            };

            let req = TaskResultRequest {
                node_id: node_id.clone(),
                task_id: task_id.clone(),
                poc_id: cached_poc_id.clone(),
                scanned_count: *scanned_count,
                hits,
            };

            match state.client.post(format!("{}/api/task/result", state.server_url))
                .header("Authorization", format!("Bearer {}", state.token))
                .json(&req)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        if body.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                            mark_reported(&state, task_id);
                            continue;
                        }
                    }
                    // Server didn't confirm ok, retry next cycle
                    break;
                }
                _ => break, // Network issue, try again next cycle
            }
        }

        // Also check for orphaned hits (reported=0 but task already reported)
        // This handles edge case where task_results marked reported but hits weren't
        let orphan_hits = {
            let db = match state.cache_db.lock() {
                Ok(db) => db,
                Err(_) => continue,
            };
            let mut stmt = match db.prepare(
                "SELECT h.task_id, h.source, h.address, h.discovered_at, COALESCE(h.poc_id,'') FROM hits h LEFT JOIN task_results t ON h.task_id = t.task_id WHERE h.reported=0 AND (t.reported=1 OR t.task_id IS NULL) LIMIT 50"
            ) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let rows: Vec<(String, String, HitRecord)> = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(4)?, HitRecord {
                    source: row.get(1)?,
                    address: row.get(2)?,
                    discovered_at: row.get(3)?,
                }))
            }).ok().map(|r| r.flatten().collect()).unwrap_or_default();
            rows
        };

        if !orphan_hits.is_empty() {
            // Group by task_id and re-report just the hits
            let mut by_task: std::collections::HashMap<String, (String, Vec<HitRecord>)> = std::collections::HashMap::new();
            for (tid, pid, hit) in orphan_hits {
                let entry = by_task.entry(tid).or_insert_with(|| (pid.clone(), Vec::new()));
                if entry.0.is_empty() && !pid.is_empty() { entry.0 = pid; }
                entry.1.push(hit);
            }

            for (task_id, (poc_id, hits)) in by_task {
                let req = TaskResultRequest {
                    node_id: node_id.clone(),
                    task_id: task_id.clone(),
                    poc_id,
                    scanned_count: 0,
                    hits,
                };

                match state.client.post(format!("{}/api/task/result", state.server_url))
                    .header("Authorization", format!("Bearer {}", state.token))
                    .json(&req)
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(body) = resp.json::<serde_json::Value>().await {
                            if body.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                                // Mark these hits as reported
                                if let Ok(db) = state.cache_db.lock() {
                                    let _ = db.execute(
                                        "UPDATE hits SET reported=1 WHERE task_id=?1 AND reported=0",
                                        rusqlite::params![task_id],
                                    );
                                }
                            }
                        }
                    }
                    _ => break,
                }
            }
        }
    }
}
