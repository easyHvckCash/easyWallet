use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use axum::middleware::Next;
use axum::response::Html;
use axum::{routing::{get, post}, Json, Router};
use base64::Engine as _;
use dashmap::DashMap;
use rusqlite::Connection;
use sysinfo::System;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::{Duration, sleep};

use crate::protocol::*;
use crate::Args;

const HEARTBEAT_TIMEOUT_SECS: u64 = 30;
const LONG_POLL_SECS: u64 = 30;
const MAX_QUEUED_TASKS: usize = 500; // default backpressure limit (can be changed at runtime)
const BATCH_SIZE: usize = 10_000;

// --- Data Structures ---

#[derive(Clone)]
struct Task {
    task_id: String,
    poc_id: String,
    task_type: String,
    batch: Vec<String>,
    depth: u32,
    retry_count: u32,
    source_file: Option<PathBuf>,
}

struct AssignedTask {
    task: Task,
    node_id: String,
    assigned_at: Instant,
    expected_secs: f64,
}

struct TaskQueue {
    pending: VecDeque<Task>,
    assigned: HashMap<String, AssignedTask>,
    completed_count: u64,
}

struct NodeInfoInner {
    node_id: String,
    gpu_name: String,
    cpu_name: String,
    hostname: String,
    total_memory_mb: u64,
    speed: f64,
    total_scanned: u64,
    total_hits: u64,
    last_heartbeat: Instant,
    connected_since: Instant,
    online: bool,
    benchmark_speed: f64,
    cpu_usage: f64,
    memory_usage: f64,
    gpu_utilization: f32,
    gpu_memory_used_mb: u64,
    gpu_memory_total_mb: u64,
    gpu_temp_c: u32,
    gpu_available: bool,
    gpu_error: String,
    compute_mode: String, // "gpu" or "cpu"
}

pub struct MasterState {
    nodes: DashMap<String, NodeInfoInner>,
    task_queue: TokioMutex<TaskQueue>,
    db: std::sync::Mutex<Connection>,
    total_hits: AtomicU64,
    total_scanned: AtomicU64,
    token: String,
    poc_base_dir: PathBuf,
    scanner_folder: PathBuf,
    depth: u32,
    poc_type_map: HashMap<String, String>,
    task_notify: tokio::sync::Notify,
    poc_processes: std::sync::Mutex<HashMap<String, PocProcessInfo>>,
    cancel_queue: std::sync::Mutex<HashMap<String, Vec<String>>>,
    // Sysinfo
    sys: std::sync::Mutex<System>,
    hostname: String,
    cpu_name: String,
    total_memory_mb: u64,
    // POC settings
    poc_max_concurrent: std::sync::Mutex<usize>,
    poc_maxfile: std::sync::Mutex<u32>,
    // Bench
    bench_running: AtomicBool,
    bench_log: std::sync::Mutex<Vec<String>>,
    bench_done: AtomicBool,
    // Reload info
    last_reload_time: std::sync::Mutex<Option<String>>,
    reload_reason: std::sync::Mutex<Option<String>>,
    // Start time
    start_time: Instant,
    // Task dispatch control
    dispatching: AtomicBool,
    enabled_nodes: std::sync::Mutex<HashSet<String>>,
    // Compute mode switch commands: node_id -> target mode
    mode_switch_queue: std::sync::Mutex<HashMap<String, String>>,
    // Task rate control
    max_queue_size: AtomicU64, // global max pending tasks (0 = use default MAX_QUEUED_TASKS)
    node_task_limits: std::sync::Mutex<HashMap<String, u64>>, // per-node max concurrent tasks (0 = unlimited)
    // Bench task queue: node_id -> BenchTask (pending for node to pick up)
    bench_task_queue: std::sync::Mutex<HashMap<String, crate::protocol::BenchTask>>,
    // Dashboard credentials
    auth_user: String,
    auth_pass: String,
}

struct PocProcessInfo {
    child: std::process::Child,
    poc_id: String,
    poc_name: String,
    output_dir: String,
    start_time: Instant,
}
impl TaskQueue {
    fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            assigned: HashMap::new(),
            completed_count: 0,
        }
    }

    fn push_task(&mut self, task: Task) {
        self.pending.push_back(task);
    }

    fn pull_task(&mut self, node_id: &str, node_speed: f64) -> Option<Task> {
        if let Some(task) = self.pending.pop_front() {
            let task_id = task.task_id.clone();
            let batch_size = task.batch.len() as f64;
            let expected_secs = if node_speed > 0.0 {
                (batch_size / node_speed) * 10.0
            } else {
                300.0 // default 5 min if speed unknown
            };
            self.assigned.insert(task_id, AssignedTask {
                task: task.clone(),
                node_id: node_id.to_string(),
                assigned_at: Instant::now(),
                expected_secs,
            });
            Some(task)
        } else {
            None
        }
    }

    fn complete_task(&mut self, task_id: &str) -> (Option<PathBuf>, String) {
        if let Some(at) = self.assigned.remove(task_id) {
            self.completed_count += 1;
            (at.task.source_file, at.task.poc_id)
        } else {
            (None, String::new())
        }
    }

    fn timeout_tasks(&mut self) -> Vec<(Task, String)> {
        let now = Instant::now();
        let expired: Vec<String> = self.assigned.iter()
            .filter(|(_, at)| {
                let elapsed = now.duration_since(at.assigned_at).as_secs_f64();
                elapsed > at.expected_secs
            })
            .map(|(id, _)| id.clone())
            .collect();
        let mut recovered = Vec::new();
        for id in expired {
            if let Some(mut at) = self.assigned.remove(&id) {
                let node_id = at.node_id.clone();
                at.task.retry_count += 1;
                recovered.push((at.task, node_id));
            }
        }
        recovered
    }
}
fn load_poc_type_map(poc_base_dir: &PathBuf) -> HashMap<String, String> {
    let info_path = poc_base_dir.join("pocinfo.json");
    let mut map = HashMap::new();
    if let Ok(content) = fs::read_to_string(&info_path) {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
            // Structure: { "vendor1": { "pocs": [...] }, "vendor2": { "pocs": [...] }, ... }
            if let Some(obj) = data.as_object() {
                for (_vendor, vendor_data) in obj {
                    if let Some(pocs) = vendor_data.get("pocs").and_then(|v| v.as_array()) {
                        for poc in pocs {
                            if let Some(id) = poc.get("id").and_then(|v| v.as_str()) {
                                let t = poc.get("output_type")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("mnemonic");
                                map.insert(id.to_string(), t.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    println!("[Config] POC type map: {:?}", map);
    map
}

fn init_master_db(folder: &PathBuf) -> Connection {
    let db_path = folder.join("master.db");
    let conn = Connection::open(&db_path).expect("Failed to open master.db");
    conn.execute_batch("
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        CREATE TABLE IF NOT EXISTS hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT,
            node_id TEXT,
            poc_id TEXT DEFAULT '',
            source TEXT,
            address TEXT,
            discovered_at TEXT,
            received_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS task_log (
            task_id TEXT PRIMARY KEY,
            poc_id TEXT,
            node_id TEXT,
            scanned_count INTEGER,
            hit_count INTEGER,
            completed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS poc_progress (
            poc_id TEXT PRIMARY KEY,
            current_index INTEGER DEFAULT 0,
            batch_num INTEGER DEFAULT 0,
            total_generated INTEGER DEFAULT 0,
            total_space INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS poc_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            poc_id TEXT NOT NULL,
            line TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_poc_logs ON poc_logs(poc_id, id);
        DROP INDEX IF EXISTS idx_hits_dedup;
    ").expect("Failed to init master DB schema");
    let _ = conn.execute("ALTER TABLE hits ADD COLUMN poc_id TEXT DEFAULT ''", []);
    conn
}
pub async fn run_master(args: Args) {
    println!("[Master] Starting on port {}", args.listenon);
    let poc_base_dir = PathBuf::from("../humanaction/pocs");
    let scanner_folder = args.folder.clone();
    let poc_type_map = load_poc_type_map(&poc_base_dir);
    let db = init_master_db(&scanner_folder);

    let mut sys = System::new_all();
    sys.refresh_all();
    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let cpu_name = sys.cpus().first()
        .map(|c| c.brand().to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let total_memory_mb = sys.total_memory() / 1024 / 1024;

    let state = Arc::new(MasterState {
        nodes: DashMap::new(),
        task_queue: TokioMutex::new(TaskQueue::new()),
        db: std::sync::Mutex::new(db),
        total_hits: AtomicU64::new(0),
        total_scanned: AtomicU64::new(0),
        token: args.token.clone(),
        poc_base_dir,
        scanner_folder: scanner_folder.clone(),
        depth: args.depth,
        poc_type_map,
        task_notify: tokio::sync::Notify::new(),
        poc_processes: std::sync::Mutex::new(HashMap::new()),
        cancel_queue: std::sync::Mutex::new(HashMap::new()),
        sys: std::sync::Mutex::new(sys),
        hostname,
        cpu_name,
        total_memory_mb,
        poc_max_concurrent: std::sync::Mutex::new(3),
        poc_maxfile: std::sync::Mutex::new(200),
        bench_running: AtomicBool::new(false),
        bench_log: std::sync::Mutex::new(Vec::new()),
        bench_done: AtomicBool::new(false),
        last_reload_time: std::sync::Mutex::new(None),
        reload_reason: std::sync::Mutex::new(None),
        start_time: Instant::now(),
        dispatching: AtomicBool::new(false),
        enabled_nodes: std::sync::Mutex::new(HashSet::new()),
        mode_switch_queue: std::sync::Mutex::new(HashMap::new()),
        max_queue_size: AtomicU64::new(MAX_QUEUED_TASKS as u64),
        node_task_limits: std::sync::Mutex::new(HashMap::new()),
        bench_task_queue: std::sync::Mutex::new(HashMap::new()),
        auth_user: args.user.clone(),
        auth_pass: args.passwd.clone(),
    });

    // Spawn watchdog for task timeouts + node health
    let wdg_state = state.clone();
    tokio::spawn(async move { watchdog_loop(wdg_state).await });

    // Spawn POC ingest loop (reads waittocheck/ and feeds queue)
    let ing_state = state.clone();
    let watch_dir = scanner_folder.join("waittocheck");
    // On startup: recover unfinished tasks from processing/ back to waittocheck/
    let processing_base = scanner_folder.join("processing");
    if processing_base.is_dir() {
        if let Ok(dirs) = fs::read_dir(&processing_base) {
            let mut recovered = 0usize;
            for dir_entry in dirs.flatten() {
                let sub = dir_entry.path();
                if !sub.is_dir() { continue; }
                let poc_id = sub.file_name().unwrap_or_default().to_string_lossy().to_string();
                let dest_dir = watch_dir.join(&poc_id);
                let _ = fs::create_dir_all(&dest_dir);
                if let Ok(files) = fs::read_dir(&sub) {
                    for f in files.flatten() {
                        let fp = f.path();
                        if fp.is_file() {
                            let fname = fp.file_name().unwrap_or_default();
                            let dest = dest_dir.join(fname);
                            let _ = fs::rename(&fp, &dest);
                            recovered += 1;
                        }
                    }
                }
            }
            if recovered > 0 {
                println!("[Recovery] Moved {} unfinished task files from processing/ back to waittocheck/", recovered);
            }
        }
    }
    tokio::spawn(async move { poc_ingest_loop(ing_state, watch_dir).await });

    // Spawn JSON export loop (writes all.json every 2 minutes for external static dashboard)
    let export_state = state.clone();
    let export_path = scanner_folder.join("all.json");
    tokio::spawn(async move { json_export_loop(export_state, export_path).await });

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.listenon))
        .await
        .expect("Failed to bind master port");
    println!("[Master] Listening on 0.0.0.0:{}", args.listenon);
    println!("[Master] Dashboard at http://localhost:{}/", args.listenon);
    axum::serve(listener, app).await.unwrap();
}
fn build_router(state: Arc<MasterState>) -> Router {
    let s = state.clone();
    let token_layer = axum::middleware::from_fn(move |req, next| {
        let st = s.clone();
        token_auth(st, req, next)
    });

    let (s1,s2,s3,s4,s5,s6,s7,s8,s9) = (
        state.clone(),state.clone(),state.clone(),state.clone(),state.clone(),
        state.clone(),state.clone(),state.clone(),state.clone(),
    );
    let (s10,s11,s12,s13,s14,s15,s16,s17,s18,s19,s20) = (
        state.clone(),state.clone(),state.clone(),state.clone(),state.clone(),
        state.clone(),state.clone(),state.clone(),state.clone(),state.clone(),
        state.clone(),
    );

    let (s21,s22,s23,s24,s25,s26,s27,s28,s29) = (state.clone(), state.clone(), state.clone(), state.clone(), state.clone(), state.clone(), state.clone(), state.clone(), state.clone());

    Router::new()
        // Cluster/node APIs
        .route("/api/node/register", post(move |body| handle_register(s1, body)))
        .route("/api/node/heartbeat", post(move |body| handle_heartbeat(s2, body)))
        .route("/api/task/pull", post(move |body| handle_task_pull(s3, body)))
        .route("/api/task/result", post(move |body| handle_task_result(s4, body)))
        .route("/api/task/hits", post(move |body| handle_task_hits(s26, body)))
        .route("/api/task/batch_results", post(move |body| handle_batch_results(s5, body)))
        .route("/api/cluster/status", get(move || handle_cluster_status(s6)))
        // Original panel APIs (adapted to cluster)
        .route("/api/status", get(move || api_status(s10)))
        .route("/api/sysinfo", get(move || api_sysinfo(s11)))
        .route("/api/results", get(move || api_results(s12)))
        .route("/api/dir_stats", get(move || api_dir_stats(s13)))
        .route("/api/pocs/list", get(move || api_pocs_list(s14)))
        .route("/api/pocs/status", get(move || api_pocs_status(s15)))
        .route("/api/pocs/start", post(move |body| handle_poc_start(s8, body)))
        .route("/api/pocs/stop", post(move |body| handle_poc_stop(s9, body)))
        .route("/api/pocs/log", post(move |body| api_pocs_log(s16, body)))
        .route("/api/pocs/reload", post(move || api_pocs_reload(s17)))
        .route("/api/pocs/reload_info", get(move || api_pocs_reload_info(s18)))
        .route("/api/pocs/settings", post(move |body| api_pocs_settings(s19, body)))
        .route("/api/pocs/edit_progress", post(move |body| api_pocs_edit_progress(s20, body)))
        .route("/api/bench/run", post(move |body| api_bench_run(s7, body)))
        .route("/api/bench/log", get(move || api_bench_log(state.clone())))
        .route("/api/bench/result", post(move |body: String| api_bench_result(s25, body)))
        .route("/api/convert", post(move |body: String| async move { api_convert(body) }))
        .route("/api/mode", post(move |_body: String| async { Json(serde_json::json!({"ok": true})) }))
        .route("/api/start", post(move |body: String| api_start(s21, body)))
        .route("/api/stop", post(move || api_stop(s22)))
        .route("/api/nodes/enable", post(move |body: String| api_nodes_enable(s23, body)))
        .route("/api/nodes/switch_mode", post(move |body: String| api_nodes_switch_mode(s24, body)))
        .route("/api/export", post(move || api_export_now(s27)))
        .route("/api/set_queue_limit", post(move |body: String| api_set_queue_limit(s28, body)))
        .route("/api/set_node_limit", post(move |body: String| api_set_node_limit(s29, body)))
        // Pages
        .route("/", get(serve_scanner_page))
        .route("/bench", get(serve_bench_page))
        .route("/results", get(serve_results_page))
        .route("/stats", get(serve_stats_page))
        .route("/pocs", get(serve_pocs_page))
        .route("/about", get(serve_about_page))
        .layer(token_layer)
}

async fn token_auth(
    state: Arc<MasterState>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let path = req.uri().path().to_string();
    // HTML pages trigger basic auth popup in browser
    if path == "/" || path == "/bench" || path == "/results"
        || path == "/stats" || path == "/pocs" || path == "/nodes"
        || path == "/about"
        || path.starts_with("/panel") {
        return basic_auth_check(&state, req, next).await;
    }
    // API endpoints: accept bearer token OR basic auth
    if let Some(auth) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(val) = auth.to_str() {
            if let Some(token) = val.strip_prefix("Bearer ") {
                if token == state.token {
                    return next.run(req).await;
                }
            }
            if let Some(encoded) = val.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                    if let Ok(cred) = String::from_utf8(decoded) {
                        let expected = format!("{}:{}", state.auth_user, state.auth_pass);
                        if cred == expected {
                            return next.run(req).await;
                        }
                    }
                }
            }
        }
    }
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"easyWallet Master\"")
        .body(Body::from("Unauthorized"))
        .unwrap()
}

async fn basic_auth_check(state: &Arc<MasterState>, req: Request<Body>, next: Next) -> Response<Body> {
    if let Some(auth) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(val) = auth.to_str() {
            if let Some(encoded) = val.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                    if let Ok(cred) = String::from_utf8(decoded) {
                        let expected = format!("{}:{}", state.auth_user, state.auth_pass);
                        if cred == expected {
                            return next.run(req).await;
                        }
                    }
                }
            }
        }
    }
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"easyWallet Master\"")
        .body(Body::from("Unauthorized"))
        .unwrap()
}

async fn handle_register(state: Arc<MasterState>, body: String) -> Response<Body> {
    let req: RegisterRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"ok":false,"error":"invalid json"}"#))
                .unwrap();
        }
    };

    let node_id = req.node_id.clone();
    if node_id.is_empty() {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"ok":false,"error":"node_id required"}"#))
            .unwrap();
    }

    // Reject if this node_id is already online
    if let Some(existing) = state.nodes.get(&node_id) {
        if existing.online {
            println!("[Master] REJECTED duplicate node_id {} (already online)", &node_id[..node_id.len().min(8)]);
            return Response::builder()
                .status(StatusCode::CONFLICT)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"ok":false,"error":"node_id already connected"}"#))
                .unwrap();
        }
    }

    let now = Instant::now();
    state.nodes.insert(node_id.clone(), NodeInfoInner {
        node_id: node_id.clone(),
        gpu_name: req.gpu_name,
        cpu_name: req.cpu_name,
        hostname: req.hostname,
        total_memory_mb: req.total_memory_mb,
        speed: req.benchmark_speed,
        total_scanned: 0,
        total_hits: 0,
        last_heartbeat: now,
        connected_since: now,
        online: true,
        benchmark_speed: req.benchmark_speed,
        cpu_usage: 0.0,
        memory_usage: 0.0,
        gpu_utilization: 0.0,
        gpu_memory_used_mb: 0,
        gpu_memory_total_mb: 0,
        gpu_temp_c: 0,
        gpu_available: req.gpu_available,
        gpu_error: req.gpu_error,
        compute_mode: req.compute_mode,
    });
    // New nodes start disabled — must be manually enabled from Scanner page
    println!("[Master] Node registered: {} (disabled by default)", &node_id[..node_id.len().min(8)]);
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"ok":true,"node_id":"{}"}}"#, node_id)))
        .unwrap()
}

async fn handle_heartbeat(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let req: HeartbeatRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return Json(serde_json::json!({"ok": false, "cancel_tasks": []})),
    };
    if let Some(mut node) = state.nodes.get_mut(&req.node_id) {
        node.speed = req.speed;
        node.total_scanned = req.total_scanned;
        node.total_hits = req.total_hits;
        node.last_heartbeat = Instant::now();
        node.online = true;
        node.cpu_usage = req.cpu_usage;
        node.memory_usage = req.memory_usage;
        node.gpu_utilization = req.gpu_utilization;
        node.gpu_memory_used_mb = req.gpu_memory_used_mb;
        node.gpu_memory_total_mb = req.gpu_memory_total_mb;
        node.gpu_temp_c = req.gpu_temp_c;
        if !req.compute_mode.is_empty() {
            node.compute_mode = req.compute_mode.clone();
        }
    }

    // Check for pending cancel commands for this node
    let cancels = if let Ok(mut cq) = state.cancel_queue.lock() {
        cq.remove(&req.node_id).unwrap_or_default()
    } else {
        vec![]
    };

    // Check for pending mode switch command
    let switch_mode = state.mode_switch_queue.lock().unwrap().remove(&req.node_id);

    // Check for pending bench task for this node
    let bench_task = state.bench_task_queue.lock().unwrap().remove(&req.node_id);

    Json(serde_json::json!({
        "ok": true,
        "cancel_tasks": cancels,
        "switch_compute_mode": switch_mode,
        "bench_task": bench_task
    }))
}

fn is_node_enabled(state: &MasterState, node_id: &str) -> bool {
    let enabled = state.enabled_nodes.lock().unwrap();
    enabled.contains(node_id)
}

async fn handle_task_pull(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let req: TaskPullRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return Json(serde_json::json!({"task": null})),
    };

    // Check if dispatching is enabled and this node is allowed
    if !state.dispatching.load(Ordering::Relaxed) {
        return Json(serde_json::json!({"task": null}));
    }
    if !is_node_enabled(&state, &req.node_id) {
        return Json(serde_json::json!({"task": null}));
    }

    // Check per-node task limit
    let node_limit = state.node_task_limits.lock().unwrap().get(&req.node_id).copied().unwrap_or(0);
    if node_limit > 0 {
        let assigned_count = state.task_queue.lock().await.assigned.values()
            .filter(|at| at.node_id == req.node_id).count() as u64;
        if assigned_count >= node_limit {
            return Json(serde_json::json!({"task": null}));
        }
    }

    // Get node speed for dynamic timeout calculation
    let node_speed = state.nodes.get(&req.node_id)
        .map(|n| if n.speed > 0.0 { n.speed } else { n.benchmark_speed })
        .unwrap_or(0.0);

    // Try immediate pull
    {
        let mut queue = state.task_queue.lock().await;
        if let Some(task) = queue.pull_task(&req.node_id, node_speed) {
            return Json(serde_json::json!({
                "task": {
                    "task_id": task.task_id,
                    "poc_id": task.poc_id,
                    "task_type": task.task_type,
                    "batch": task.batch,
                    "depth": task.depth,
                }
            }));
        }
    }

    // Long-poll: wait up to LONG_POLL_SECS for new tasks
    let timeout = tokio::time::timeout(
        Duration::from_secs(LONG_POLL_SECS),
        state.task_notify.notified(),
    ).await;

    if timeout.is_ok() {
        let mut queue = state.task_queue.lock().await;
        if let Some(task) = queue.pull_task(&req.node_id, node_speed) {
            return Json(serde_json::json!({
                "task": {
                    "task_id": task.task_id,
                    "poc_id": task.poc_id,
                    "task_type": task.task_type,
                    "batch": task.batch,
                    "depth": task.depth,
                }
            }));
        }
    }

    Json(serde_json::json!({"task": null}))
}

async fn handle_task_result(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let req: TaskResultRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return Json(serde_json::json!({"ok": false})),
    };

    // Mark task complete
    let mut queue = state.task_queue.lock().await;
    let (source_file, queue_poc_id) = queue.complete_task(&req.task_id);
    drop(queue);

    let poc_id = if !req.poc_id.is_empty() { req.poc_id.clone() } else { queue_poc_id };
    if poc_id.is_empty() {
        eprintln!("[WARN] Task {} completed with empty poc_id (node: {})", &req.task_id[..8.min(req.task_id.len())], &req.node_id[..8.min(req.node_id.len())]);
    }

    // Move source file to done/ directory
    if let Some(ref src) = source_file {
        move_to_done(src, &state.scanner_folder);
    }

    state.total_scanned.fetch_add(req.scanned_count, Ordering::Relaxed);
    state.total_hits.fetch_add(req.hits.len() as u64, Ordering::Relaxed);

    // Persist hits to DB
    if !req.hits.is_empty() {
        if let Ok(db) = state.db.lock() {
            for hit in &req.hits {
                let _ = db.execute(
                    "INSERT INTO hits (task_id, node_id, poc_id, source, address, discovered_at) VALUES (?1,?2,?3,?4,?5,?6)",
                    rusqlite::params![req.task_id, req.node_id, poc_id, hit.source, hit.address, hit.discovered_at],
                );
            }
        }
        println!("[Master] HIT! {} hits from node {} task {}",
            req.hits.len(), &req.node_id[..8], &req.task_id[..8]);
    }

    // Log task completion - count hits from hits table since they arrive via immediate report
    if let Ok(db) = state.db.lock() {
        let hit_count: u64 = db.query_row(
            "SELECT COUNT(*) FROM hits WHERE task_id=?1",
            rusqlite::params![req.task_id],
            |row| row.get(0),
        ).unwrap_or(0);
        let _ = db.execute(
            "INSERT OR REPLACE INTO task_log (task_id, poc_id, node_id, scanned_count, hit_count, completed_at) VALUES (?1,?2,?3,?4,?5,datetime('now'))",
            rusqlite::params![req.task_id, poc_id, req.node_id, req.scanned_count, hit_count],
        );
    }

    Json(serde_json::json!({"ok": true}))
}

async fn handle_task_hits(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return Json(serde_json::json!({"ok": false})),
    };
    let node_id = parsed.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
    let task_id = parsed.get("task_id").and_then(|v| v.as_str()).unwrap_or("");
    let hits: Vec<HitRecord> = parsed.get("hits")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    if hits.is_empty() {
        return Json(serde_json::json!({"ok": true}));
    }

    let poc_id = {
        let from_req = parsed.get("poc_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !from_req.is_empty() {
            from_req
        } else {
            let queue = state.task_queue.lock().await;
            queue.assigned.get(task_id).map(|a| a.task.poc_id.clone()).unwrap_or_default()
        }
    };

    state.total_hits.fetch_add(hits.len() as u64, Ordering::Relaxed);

    if let Ok(db) = state.db.lock() {
        for hit in &hits {
            let _ = db.execute(
                "INSERT INTO hits (task_id, node_id, poc_id, source, address, discovered_at) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![task_id, node_id, poc_id, hit.source, hit.address, hit.discovered_at],
            );
        }
    }
    println!("[Master] IMMEDIATE HIT! {} hits from node {} task {}",
        hits.len(), &node_id[..node_id.len().min(8)], &task_id[..task_id.len().min(8)]);

    Json(serde_json::json!({"ok": true}))
}

async fn handle_batch_results(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let req: BatchResultsRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return Json(serde_json::json!({"ok": false, "accepted": 0})),
    };
    let count = req.results.len();
    for result in req.results {
        let mut queue = state.task_queue.lock().await;
        let (source_file, queue_poc_id) = queue.complete_task(&result.task_id);
        drop(queue);

        let poc_id = if !result.poc_id.is_empty() { result.poc_id.clone() } else { queue_poc_id };
        if poc_id.is_empty() {
            eprintln!("[WARN] Batch task {} completed with empty poc_id (node: {})", &result.task_id[..8.min(result.task_id.len())], &result.node_id[..8.min(result.node_id.len())]);
        }

        if let Some(ref src) = source_file {
            move_to_done(src, &state.scanner_folder);
        }

        state.total_scanned.fetch_add(result.scanned_count, Ordering::Relaxed);
        state.total_hits.fetch_add(result.hits.len() as u64, Ordering::Relaxed);

        if !result.hits.is_empty() {
            if let Ok(db) = state.db.lock() {
                for hit in &result.hits {
                    let _ = db.execute(
                        "INSERT INTO hits (task_id, node_id, poc_id, source, address, discovered_at) VALUES (?1,?2,?3,?4,?5,?6)",
                        rusqlite::params![result.task_id, result.node_id, poc_id, hit.source, hit.address, hit.discovered_at],
                    );
                }
            }
        }

        if let Ok(db) = state.db.lock() {
            let hit_count: u64 = db.query_row(
                "SELECT COUNT(*) FROM hits WHERE task_id=?1",
                rusqlite::params![result.task_id],
                |row| row.get(0),
            ).unwrap_or(0);
            let _ = db.execute(
                "INSERT OR REPLACE INTO task_log (task_id, poc_id, node_id, scanned_count, hit_count, completed_at) VALUES (?1,?2,?3,?4,?5,datetime('now'))",
                rusqlite::params![result.task_id, poc_id, result.node_id, result.scanned_count, hit_count],
            );
        }
    }
    Json(serde_json::json!({"ok": true, "accepted": count}))
}

async fn handle_cluster_status(state: Arc<MasterState>) -> Json<serde_json::Value> {
    let queue = state.task_queue.lock().await;
    let pending = queue.pending.len();
    let assigned = queue.assigned.len();
    let completed = queue.completed_count;
    drop(queue);

    let mut nodes_info = Vec::new();
    let mut online_count = 0;
    let mut total_speed = 0.0;
    let enabled_set = state.enabled_nodes.lock().unwrap().clone();
    let limits = state.node_task_limits.lock().unwrap().clone();

    for entry in state.nodes.iter() {
        let n = entry.value();
        let secs_ago = n.last_heartbeat.elapsed().as_secs_f64();
        if n.online { online_count += 1; }
        total_speed += n.speed;
        let node_enabled = enabled_set.contains(&n.node_id);
        let task_limit = limits.get(&n.node_id).copied().unwrap_or(0);
        nodes_info.push(serde_json::json!({
            "node_id": n.node_id,
            "gpu_name": n.gpu_name,
            "cpu_name": n.cpu_name,
            "hostname": n.hostname,
            "speed": n.speed,
            "benchmark_speed": n.benchmark_speed,
            "total_scanned": n.total_scanned,
            "total_hits": n.total_hits,
            "cpu_usage": n.cpu_usage,
            "memory_usage": n.memory_usage,
            "gpu_util": n.gpu_utilization,
            "gpu_mem_used_mb": n.gpu_memory_used_mb,
            "gpu_mem_total_mb": n.gpu_memory_total_mb,
            "gpu_temp_c": n.gpu_temp_c,
            "gpu_available": n.gpu_available,
            "gpu_error": n.gpu_error,
            "compute_mode": n.compute_mode,
            "enabled": node_enabled,
            "task_limit": task_limit,
            "status": if n.online { "online" } else { "offline" },
            "last_heartbeat_secs_ago": secs_ago,
        }));
    }

    let mqs_val = state.max_queue_size.load(Ordering::Relaxed);
    let mqs_out = if mqs_val == u64::MAX { 0u64 } else { mqs_val };

    Json(serde_json::json!({
        "total_nodes": state.nodes.len(),
        "online_nodes": online_count,
        "total_speed": total_speed,
        "total_scanned": state.total_scanned.load(Ordering::Relaxed),
        "total_hits": state.total_hits.load(Ordering::Relaxed),
        "pending_tasks": pending,
        "assigned_tasks": assigned,
        "completed_tasks": completed,
        "max_queue_size": mqs_out,
        "nodes": nodes_info,
    }))
}

async fn handle_poc_start(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let poc_id = match parsed.get("poc_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return Json(serde_json::json!({"ok": false, "error": "missing poc_id"})),
    };
    let poc_name = parsed.get("poc_name").and_then(|v| v.as_str())
        .unwrap_or(&poc_id).to_string();

    // Check if already running
    if let Ok(procs) = state.poc_processes.lock() {
        if procs.contains_key(&poc_id) {
            return Json(serde_json::json!({"ok": false, "error": "This POC is already running"}));
        }
    }

    let maxfile = *state.poc_maxfile.lock().unwrap();
    let output_dir = state.scanner_folder.join("waittocheck").join(&poc_id);
    let _ = fs::create_dir_all(&output_dir);

    let output_dir_abs = fs::canonicalize(&output_dir)
        .unwrap_or_else(|_| output_dir.clone())
        .to_string_lossy().replace('\\', "/");

    // Read resume position from progress table
    let (start_index, start_batch) = {
        let db = state.db.lock().unwrap();
        let mut idx = 0i64;
        let mut batch = 0i64;
        if let Ok(mut stmt) = db.prepare("SELECT current_index, batch_num FROM poc_progress WHERE poc_id=?1") {
            if let Ok(row) = stmt.query_row([&poc_id], |r| Ok((r.get::<_, i64>(0).unwrap_or(0), r.get::<_, i64>(1).unwrap_or(0)))) {
                idx = row.0;
                batch = row.1;
            }
        }
        (idx, batch)
    };

    let py_cmd = if cfg!(windows) { "py" } else { "python3" };
    let mf_str = maxfile.to_string();
    let idx_str = start_index.to_string();
    let batch_str = start_batch.to_string();

    let mut cmd = std::process::Command::new(py_cmd);
    if cfg!(windows) { cmd.arg("-3"); }
    cmd.arg("main.py")
        .arg("--poc").arg(&poc_id)
        .arg("--output").arg(&output_dir_abs)
        .arg("--maxfile").arg(&mf_str)
        .arg("--start-index").arg(&idx_str)
        .arg("--start-batch").arg(&batch_str)
        .env("PYTHONIOENCODING", "utf-8")
        .current_dir(&state.poc_base_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let child = cmd.spawn();

    match child {
        Ok(mut c) => {
            let stdout = c.stdout.take();
            let stderr = c.stderr.take();

            if let Ok(mut procs) = state.poc_processes.lock() {
                procs.insert(poc_id.clone(), PocProcessInfo {
                    child: c,
                    poc_id: poc_id.clone(),
                    poc_name,
                    output_dir: output_dir_abs.clone(),
                    start_time: Instant::now(),
                });
            }

            // Spawn stdout reader thread
            let db_path = state.scanner_folder.join("master.db");
            if let Some(stdout) = stdout {
                let poc_id_c = poc_id.clone();
                let db_path_c = db_path.clone();
                std::thread::spawn(move || {
                    use std::io::{BufRead, BufReader};
                    let reader = BufReader::new(stdout);
                    for line in reader.lines().flatten() {
                        if line.starts_with("##PROGRESS## ") {
                            let json_str = &line["##PROGRESS## ".len()..];
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) {
                                let idx = v.get("index").and_then(|x| x.as_i64()).unwrap_or(0);
                                let batch = v.get("batch_num").and_then(|x| x.as_i64()).unwrap_or(0);
                                let gen = v.get("total_generated").and_then(|x| x.as_i64()).unwrap_or(0);
                                let space = v.get("total_space").and_then(|x| x.as_i64()).unwrap_or(0);
                                if let Ok(conn) = rusqlite::Connection::open(&db_path_c) {
                                    let _ = conn.execute(
                                        "INSERT INTO poc_progress (poc_id, current_index, batch_num, total_generated, total_space, updated_at) \
                                         VALUES (?1, ?2, ?3, ?4, ?5, datetime('now','localtime')) \
                                         ON CONFLICT(poc_id) DO UPDATE SET current_index=?2, batch_num=?3, total_generated=?4, total_space=?5, updated_at=datetime('now','localtime')",
                                        rusqlite::params![poc_id_c, idx, batch, gen, space],
                                    );
                                }
                            }
                        } else if line.starts_with("##LOG## ") {
                            let msg = &line["##LOG## ".len()..];
                            insert_poc_log(&db_path_c, &poc_id_c, msg);
                        } else if !line.is_empty() {
                            insert_poc_log(&db_path_c, &poc_id_c, &line);
                        }
                    }
                });
            }

            // Spawn stderr reader thread
            if let Some(stderr) = stderr {
                let poc_id_c = poc_id.clone();
                let db_path_c = db_path;
                std::thread::spawn(move || {
                    use std::io::{BufRead, BufReader};
                    let reader = BufReader::new(stderr);
                    for line in reader.lines().flatten() {
                        if !line.is_empty() {
                            insert_poc_log(&db_path_c, &poc_id_c, &format!("[stderr] {}", line));
                        }
                    }
                });
            }

            println!("[Master] POC started: {}", poc_id);
            Json(serde_json::json!({"ok": true, "poc_id": poc_id}))
        }
        Err(e) => {
            Json(serde_json::json!({"ok": false, "error": format!("spawn failed: {}", e)}))
        }
    }
}

fn insert_poc_log(db_path: &PathBuf, poc_id: &str, msg: &str) {
    if let Ok(conn) = rusqlite::Connection::open(db_path) {
        let _ = conn.execute(
            "INSERT INTO poc_logs (poc_id, line) VALUES (?1, ?2)",
            rusqlite::params![poc_id, msg],
        );
        let _ = conn.execute(
            "DELETE FROM poc_logs WHERE poc_id=?1 AND id NOT IN (SELECT id FROM poc_logs WHERE poc_id=?1 ORDER BY id DESC LIMIT 200)",
            rusqlite::params![poc_id],
        );
    }
}

async fn handle_poc_stop(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let poc_id = match parsed.get("poc_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return Json(serde_json::json!({"ok": false, "error": "missing poc_id"})),
    };

    if let Ok(mut procs) = state.poc_processes.lock() {
        if let Some(mut info) = procs.remove(&poc_id) {
            let _ = info.child.kill();
            println!("[Master] POC stopped: {}", poc_id);
            return Json(serde_json::json!({"ok": true}));
        }
    }
    Json(serde_json::json!({"ok": false, "error": "not running"}))
}
async fn watchdog_loop(state: Arc<MasterState>) {
    loop {
        sleep(Duration::from_secs(10)).await;

        // Check for timed-out tasks (dynamic timeout per task)
        let recovered = {
            let mut queue = state.task_queue.lock().await;
            queue.timeout_tasks()
        };
        if !recovered.is_empty() {
            println!("[Watchdog] Re-queued {} timed-out tasks", recovered.len());

            // Send cancel commands to nodes
            if let Ok(mut cq) = state.cancel_queue.lock() {
                for (ref task, ref node_id) in &recovered {
                    cq.entry(node_id.clone())
                        .or_insert_with(Vec::new)
                        .push(task.task_id.clone());
                }
            }

            let mut queue = state.task_queue.lock().await;
            for (task, _node_id) in recovered {
                // Restore source file from processing/ back to waittocheck/
                if let Some(ref src) = task.source_file {
                    restore_file_to_waittocheck(src, &state.scanner_folder);
                }
                queue.push_task(task);
            }
            state.task_notify.notify_waiters();
        }

        // Check for offline nodes
        for mut entry in state.nodes.iter_mut() {
            let n = entry.value_mut();
            if n.online && n.last_heartbeat.elapsed().as_secs() > HEARTBEAT_TIMEOUT_SECS {
                println!("[Watchdog] Node {} went offline", &n.node_id[..8]);
                n.online = false;
                let node_id = n.node_id.clone();
                drop(entry);
                let mut queue = state.task_queue.lock().await;
                let orphaned: Vec<String> = queue.assigned.iter()
                    .filter(|(_, at)| at.node_id == node_id)
                    .map(|(id, _)| id.clone())
                    .collect();
                for tid in orphaned {
                    if let Some(at) = queue.assigned.remove(&tid) {
                        if let Some(ref src) = at.task.source_file {
                            restore_file_to_waittocheck(src, &state.scanner_folder);
                        }
                        queue.pending.push_back(at.task);
                    }
                }
                if !queue.pending.is_empty() {
                    state.task_notify.notify_waiters();
                }
                break;
            }
        }
    }
}

fn restore_file_to_waittocheck(processing_path: &PathBuf, scanner_folder: &PathBuf) {
    if !processing_path.exists() { return; }
    let file_name = processing_path.file_name().unwrap_or_default();
    let poc_dir = processing_path.parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let dest_dir = scanner_folder.join("waittocheck").join(poc_dir);
    let _ = fs::create_dir_all(&dest_dir);
    let dest = dest_dir.join(file_name);
    if let Err(e) = fs::rename(processing_path, &dest) {
        if let Ok(_) = fs::copy(processing_path, &dest) {
            let _ = fs::remove_file(processing_path);
        } else {
            eprintln!("[Watchdog] Failed to restore file {:?}: {}", processing_path, e);
        }
    }
}

fn move_to_done(processing_path: &PathBuf, _scanner_folder: &PathBuf) {
    if !processing_path.exists() { return; }
    let _ = fs::remove_file(processing_path);
}
async fn poc_ingest_loop(state: Arc<MasterState>, watch_dir: PathBuf) {
    let _ = fs::create_dir_all(&watch_dir);
    println!("[Ingest] Watching {:?} for batch files", watch_dir);

    loop {
        sleep(Duration::from_millis(1000)).await;

        // Only ingest when dispatching is active
        if !state.dispatching.load(Ordering::Relaxed) {
            continue;
        }

        // Backpressure: if queue already has enough tasks, skip this round
        let max_q = state.max_queue_size.load(Ordering::Relaxed) as usize;
        let pending_count = state.task_queue.lock().await.pending.len();
        if pending_count >= max_q {
            continue;
        }

        let entries = match fs::read_dir(&watch_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                // Check subdirectories (poc_id subdirs)
                if path.is_dir() {
                    if let Ok(sub_entries) = fs::read_dir(&path) {
                        for sub in sub_entries.flatten() {
                            let sub_path = sub.path();
                            if sub_path.is_file() && sub_path.extension().map(|e| e == "txt").unwrap_or(false) {
                                ingest_file(&state, &sub_path).await;
                            }
                        }
                    }
                }
                continue;
            }
            if path.extension().map(|e| e == "txt").unwrap_or(false) {
                ingest_file(&state, &path).await;
            }
        }
    }
}

async fn ingest_file(state: &Arc<MasterState>, path: &std::path::Path) {
    use std::io::{BufRead, BufReader};

    let content = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let reader = BufReader::new(content);
    let lines: Vec<String> = reader.lines().flatten()
        .filter(|l| !l.trim().is_empty())
        .collect();

    if lines.is_empty() {
        let _ = fs::remove_file(path);
        return;
    }

    // Determine poc_id from parent dir name or filename
    let parent_name = path.parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    let poc_id = if parent_name == "waittocheck" || parent_name.is_empty() {
        // File is directly in waittocheck/ root, extract poc_id from filename
        // Filename pattern: <poc_id>_batch_<num>_<hash>.txt
        let fname = path.file_stem().and_then(|n| n.to_str()).unwrap_or("");
        if let Some(idx) = fname.find("_batch_") {
            fname[..idx].to_string()
        } else {
            "unknown".to_string()
        }
    } else {
        parent_name
    };

    let task_type = state.poc_type_map.get(&poc_id)
        .cloned()
        .unwrap_or_else(|| "mnemonic".to_string());

    // Move file to processing/ directory (not delete!)
    let processing_dir = state.scanner_folder.join("processing").join(&poc_id);
    let _ = fs::create_dir_all(&processing_dir);
    let file_name = path.file_name().unwrap_or_default();
    let processing_path = processing_dir.join(file_name);

    if let Err(e) = fs::rename(path, &processing_path) {
        if let Ok(_) = fs::copy(path, &processing_path) {
            let _ = fs::remove_file(path);
        } else {
            eprintln!("[Ingest] Failed to move {:?}: {}", path, e);
            return;
        }
    }

    // Split into batches of BATCH_SIZE
    let source_file = Some(processing_path.clone());
    let batch_count = (lines.len() + BATCH_SIZE - 1) / BATCH_SIZE;
    println!("[Ingest] {} -> {} mnemonics, {} tasks (poc: {})", 
        path.file_name().unwrap_or_default().to_string_lossy(), lines.len(), batch_count, poc_id);
    let mut queue = state.task_queue.lock().await;
    for chunk in lines.chunks(BATCH_SIZE) {
        let task_id = uuid::Uuid::new_v4().to_string();
        queue.push_task(Task {
            task_id,
            poc_id: poc_id.clone(),
            task_type: task_type.clone(),
            batch: chunk.to_vec(),
            depth: state.depth,
            retry_count: 0,
            source_file: source_file.clone(),
        });
    }
    drop(queue);
    state.task_notify.notify_waiters();
}

async fn json_export_loop(state: Arc<MasterState>, export_path: PathBuf) {
    println!("[Export] Writing {:?} every 2 minutes", export_path);
    let tuomin_path = export_path.with_file_name("tuomin_all.json");

    loop {
        let json = build_export_json(&state).await;
        let tmp_path = export_path.with_extension("json.tmp");
        if let Ok(()) = fs::write(&tmp_path, json.as_bytes()) {
            let _ = fs::rename(&tmp_path, &export_path);
        }
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&json) {
            let masked = build_tuomin_json(&data);
            let tmp2 = tuomin_path.with_extension("json.tmp");
            if let Ok(()) = fs::write(&tmp2, masked.as_bytes()) {
                let _ = fs::rename(&tmp2, &tuomin_path);
            }
        }
        sleep(Duration::from_secs(120)).await;
    }
}

fn mask_str(s: &str, keep_start: usize, keep_end: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    if len <= keep_start + keep_end + 1 {
        return s.to_string();
    }
    let start: String = chars[..keep_start].iter().collect();
    let end: String = chars[len - keep_end..].iter().collect();
    format!("{}****{}", start, end)
}

fn mask_hostname(s: &str) -> String {
    mask_str(s.trim(), 2, 2)
}

fn mask_address(s: &str) -> String {
    mask_str(s, 4, 4)
}

fn mask_source(s: &str) -> String {
    let words: Vec<&str> = s.split_whitespace().collect();
    if words.len() >= 3 {
        format!("{} **** {}", words[0], words[words.len() - 1])
    } else if s.len() > 8 {
        mask_str(s, 4, 4)
    } else {
        s.to_string()
    }
}

fn mask_poc_id(s: &str) -> String {
    mask_str(s, 2, 2)
}

fn build_tuomin_json(data: &serde_json::Value) -> String {
    let mut d = data.clone();

    let private_pocs: std::collections::HashSet<String> = {
        let mut set = std::collections::HashSet::new();
        if let Some(poc_list) = d.get("poc_list").and_then(|v| v.as_array()) {
            for group in poc_list {
                if let Some(pocs) = group.get("pocs").and_then(|v| v.as_array()) {
                    for poc in pocs {
                        let is_public = poc.get("public").and_then(|v| v.as_bool()).unwrap_or(false);
                        if !is_public {
                            if let Some(id) = poc.get("id").and_then(|v| v.as_str()) {
                                set.insert(id.to_string());
                            }
                        }
                    }
                }
            }
        }
        set
    };

    if let Some(sysinfo) = d.get_mut("sysinfo").and_then(|v| v.as_object_mut()) {
        if let Some(h) = sysinfo.get("hostname").and_then(|v| v.as_str()).map(|s| mask_hostname(s)) {
            sysinfo.insert("hostname".to_string(), serde_json::json!(h));
        }
    }

    if let Some(nodes) = d.get_mut("nodes").and_then(|v| v.as_array_mut()) {
        for node in nodes.iter_mut() {
            if let Some(obj) = node.as_object_mut() {
                if let Some(h) = obj.get("hostname").and_then(|v| v.as_str()).map(|s| mask_hostname(s)) {
                    obj.insert("hostname".to_string(), serde_json::json!(h));
                }
            }
        }
    }

    if let Some(hits) = d.get_mut("recent_hits").and_then(|v| v.as_array_mut()) {
        for hit in hits.iter_mut() {
            if let Some(obj) = hit.as_object_mut() {
                if let Some(addr) = obj.get("address").and_then(|v| v.as_str()).map(|s| mask_address(s)) {
                    obj.insert("address".to_string(), serde_json::json!(addr));
                }
                if let Some(src) = obj.get("source").and_then(|v| v.as_str()).map(|s| mask_source(s)) {
                    obj.insert("source".to_string(), serde_json::json!(src));
                }
                if let Some(pid) = obj.get("poc_id").and_then(|v| v.as_str()) {
                    if private_pocs.contains(pid) {
                        obj.insert("poc_id".to_string(), serde_json::json!(mask_poc_id(pid)));
                    }
                }
            }
        }
    }

    if let Some(poc_list) = d.get_mut("poc_list").and_then(|v| v.as_array_mut()) {
        for group in poc_list.iter_mut() {
            let has_private = group.get("pocs").and_then(|v| v.as_array()).map(|pocs| {
                pocs.iter().any(|p| !p.get("public").and_then(|v| v.as_bool()).unwrap_or(false))
            }).unwrap_or(false);
            if has_private {
                if let Some(obj) = group.as_object_mut() {
                    if let Some(p) = obj.get("product").and_then(|v| v.as_str()).map(|s| mask_str(s, 2, 2)) {
                        obj.insert("product".to_string(), serde_json::json!(p));
                    }
                }
            }
            if let Some(pocs) = group.get_mut("pocs").and_then(|v| v.as_array_mut()) {
                for poc in pocs.iter_mut() {
                    if let Some(obj) = poc.as_object_mut() {
                        let is_public = obj.get("public").and_then(|v| v.as_bool()).unwrap_or(false);
                        if !is_public {
                            if let Some(id) = obj.get("id").and_then(|v| v.as_str()).map(|s| mask_poc_id(s)) {
                                obj.insert("id".to_string(), serde_json::json!(id));
                            }
                            if let Some(name) = obj.get("name").and_then(|v| v.as_str()).map(|s| mask_str(s, 2, 2)) {
                                obj.insert("name".to_string(), serde_json::json!(name));
                            }
                            if let Some(v) = obj.get("vendor").and_then(|v| v.as_str()).map(|s| mask_str(s, 2, 2)) {
                                obj.insert("vendor".to_string(), serde_json::json!(v));
                            }
                            if let Some(n) = obj.get("note").and_then(|v| v.as_str()).map(|s| mask_str(s, 2, 2)) {
                                obj.insert("note".to_string(), serde_json::json!(n));
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(poc_running) = d.get_mut("poc_running").and_then(|v| v.as_array_mut()) {
        for item in poc_running.iter_mut() {
            if let Some(obj) = item.as_object_mut() {
                if let Some(pid) = obj.get("poc_id").and_then(|v| v.as_str()) {
                    if private_pocs.contains(pid) {
                        let masked = mask_poc_id(pid);
                        obj.insert("poc_id".to_string(), serde_json::json!(masked));
                        if let Some(name) = obj.get("poc_name").and_then(|v| v.as_str()).map(|s| mask_str(s, 2, 2)) {
                            obj.insert("poc_name".to_string(), serde_json::json!(name));
                        }
                    }
                }
            }
        }
    }

    if let Some(stats) = d.get_mut("stats").and_then(|v| v.as_object_mut()) {
        if let Some(by_poc) = stats.get_mut("by_poc").and_then(|v| v.as_object_mut()) {
            let keys: Vec<String> = by_poc.keys().cloned().collect();
            for k in keys {
                if private_pocs.contains(&k) {
                    if let Some(val) = by_poc.remove(&k) {
                        by_poc.insert(mask_poc_id(&k), val);
                    }
                }
            }
        }
        if let Some(by_node) = stats.get_mut("by_node").and_then(|v| v.as_array_mut()) {
            for item in by_node.iter_mut() {
                if let Some(obj) = item.as_object_mut() {
                    if let Some(pid) = obj.get("poc_id").and_then(|v| v.as_str()) {
                        if private_pocs.contains(pid) {
                            obj.insert("poc_id".to_string(), serde_json::json!(mask_poc_id(pid)));
                        }
                    }
                }
            }
        }
    }

    if let Some(poc_progress) = d.get_mut("poc_progress").and_then(|v| v.as_object_mut()) {
        let keys: Vec<String> = poc_progress.keys().cloned().collect();
        for k in keys {
            if private_pocs.contains(&k) {
                if let Some(val) = poc_progress.remove(&k) {
                    poc_progress.insert(mask_poc_id(&k), val);
                }
            }
        }
    }

    serde_json::to_string_pretty(&d).unwrap_or_else(|_| "{}".to_string())
}

async fn build_export_json(state: &Arc<MasterState>) -> String {
    let queue = state.task_queue.lock().await;
    let pending = queue.pending.len();
    let assigned = queue.assigned.len();
    let completed = queue.completed_count;
    drop(queue);

    let mut nodes_info = Vec::new();
    let mut online_count = 0;
    let mut total_speed = 0.0;
    let enabled_set = state.enabled_nodes.lock().unwrap().clone();

    for entry in state.nodes.iter() {
        let n = entry.value();
        let secs_ago = n.last_heartbeat.elapsed().as_secs_f64();
        if n.online { online_count += 1; }
        total_speed += n.speed;
        nodes_info.push(serde_json::json!({
            "node_id": n.node_id,
            "gpu_name": n.gpu_name,
            "cpu_name": n.cpu_name,
            "hostname": n.hostname,
            "speed": n.speed,
            "benchmark_speed": n.benchmark_speed,
            "total_scanned": n.total_scanned,
            "total_hits": n.total_hits,
            "cpu_usage": n.cpu_usage,
            "memory_usage": n.memory_usage,
            "gpu_util": n.gpu_utilization,
            "gpu_mem_used_mb": n.gpu_memory_used_mb,
            "gpu_mem_total_mb": n.gpu_memory_total_mb,
            "gpu_temp_c": n.gpu_temp_c,
            "gpu_available": n.gpu_available,
            "gpu_error": n.gpu_error,
            "compute_mode": n.compute_mode,
            "enabled": enabled_set.contains(&n.node_id),
            "status": if n.online { "online" } else { "offline" },
            "last_heartbeat_secs_ago": secs_ago,
        }));
    }

    // Hits
    let hits = {
        let db = state.db.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT task_id, node_id, source, address, discovered_at, received_at, poc_id FROM hits ORDER BY id DESC LIMIT 100"
        ).unwrap();
        let rows: Vec<serde_json::Value> = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "task_id": row.get::<_, String>(0).unwrap_or_default(),
                "node_id": row.get::<_, String>(1).unwrap_or_default(),
                "source": row.get::<_, String>(2).unwrap_or_default(),
                "address": row.get::<_, String>(3).unwrap_or_default(),
                "discovered_at": row.get::<_, String>(4).unwrap_or_default(),
                "received_at": row.get::<_, String>(5).unwrap_or_default(),
                "poc_id": row.get::<_, String>(6).unwrap_or_default(),
            }))
        }).unwrap().flatten().collect();
        rows
    };

    // Stats (by_poc + by_node)
    let (by_poc, by_node) = {
        let db = state.db.lock().unwrap();
        let mut poc_map = serde_json::Map::new();
        if let Ok(mut stmt) = db.prepare(
            "SELECT t.poc_id, SUM(t.scanned_count), COUNT(*), MAX(t.completed_at), COALESCE(hc.cnt,0) \
             FROM task_log t \
             LEFT JOIN (SELECT COALESCE(poc_id,'') as pid, COUNT(*) as cnt FROM hits GROUP BY pid) hc ON hc.pid=t.poc_id \
             GROUP BY t.poc_id"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0).unwrap_or_default(),
                    row.get::<_, u64>(1).unwrap_or(0),
                    row.get::<_, u64>(2).unwrap_or(0),
                    row.get::<_, String>(3).unwrap_or_default(),
                    row.get::<_, u64>(4).unwrap_or(0),
                ))
            }) {
                for r in rows.flatten() {
                    poc_map.insert(r.0.clone(), serde_json::json!({
                        "files_processed": r.2,
                        "mnemonics_scanned": r.1,
                        "hits": r.4,
                        "last_time": r.3,
                    }));
                }
            }
        }
        let mut node_vec: Vec<serde_json::Value> = Vec::new();
        if let Ok(mut stmt) = db.prepare(
            "SELECT t.node_id, t.poc_id, SUM(t.scanned_count), COUNT(*), MAX(t.completed_at), \
             (SELECT COUNT(*) FROM hits h WHERE h.node_id=t.node_id AND COALESCE(h.poc_id,'')=t.poc_id) \
             FROM task_log t GROUP BY t.node_id, t.poc_id ORDER BY t.node_id, t.poc_id"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "node_id": row.get::<_, String>(0).unwrap_or_default(),
                    "poc_id": row.get::<_, String>(1).unwrap_or_default(),
                    "scanned": row.get::<_, u64>(2).unwrap_or(0),
                    "hits": row.get::<_, u64>(5).unwrap_or(0),
                    "tasks": row.get::<_, u64>(3).unwrap_or(0),
                    "last_time": row.get::<_, String>(4).unwrap_or_default(),
                }))
            }) {
                node_vec = rows.flatten().collect();
            }
        }
        (serde_json::Value::Object(poc_map), node_vec)
    };

    // POC progress
    let poc_progress = {
        let db = state.db.lock().unwrap();
        let mut map = serde_json::Map::new();
        if let Ok(mut stmt) = db.prepare("SELECT poc_id, current_index, batch_num, total_generated, total_space, updated_at FROM poc_progress") {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0).unwrap_or_default(),
                    row.get::<_, i64>(1).unwrap_or(0),
                    row.get::<_, i64>(2).unwrap_or(0),
                    row.get::<_, i64>(3).unwrap_or(0),
                    row.get::<_, i64>(4).unwrap_or(0),
                    row.get::<_, String>(5).unwrap_or_default(),
                ))
            }) {
                for r in rows.flatten() {
                    map.insert(r.0.clone(), serde_json::json!({
                        "current_index": r.1,
                        "batch_num": r.2,
                        "total_generated": r.3,
                        "total_space": r.4,
                        "timestamp": r.5,
                    }));
                }
            }
        }
        serde_json::Value::Object(map)
    };

    // POC list (from pocinfo.json) + running status
    let poc_list = {
        let pocinfo_path = state.poc_base_dir.join("pocinfo.json");
        let mut groups = Vec::new();
        if let Ok(content) = std::fs::read_to_string(&pocinfo_path) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(vendors) = data.as_object() {
                    for (_vk, vd) in vendors {
                        let product = vd.get("product").and_then(|v| v.as_str()).unwrap_or(_vk).to_string();
                        let vendor = vd.get("vendor").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let mut poc_items = Vec::new();
                        let items: Vec<&serde_json::Value> = vd.get("pocs").and_then(|p| p.as_array()).into_iter().flatten().collect();
                        for poc in items {
                            let id = poc.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            let name = poc.get("name").or_else(|| poc.get("title")).and_then(|v| v.as_str()).unwrap_or("");
                            let versions = match poc.get("affected_versions") {
                                Some(v) if v.is_array() => v.clone(),
                                Some(v) if v.is_string() => serde_json::json!([v.as_str().unwrap_or("")]),
                                _ => serde_json::json!([]),
                            };
                            poc_items.push(serde_json::json!({
                                "id": id, "name": name,
                                "output_type": poc.get("output_type").and_then(|v| v.as_str()).unwrap_or("unknown"),
                                "severity": poc.get("severity").or(poc.get("risk_level")).and_then(|v| v.as_str()).unwrap_or(""),
                                "public": poc.get("public").and_then(|v| v.as_bool()).unwrap_or(false),
                                "is_fixed": poc.get("is_fixed").and_then(|v| v.as_bool()).unwrap_or(false),
                                "generation_speed": poc.get("generation_speed").and_then(|v| v.as_str()).unwrap_or(""),
                                "coverage_time_range": poc.get("coverage_time_range").and_then(|v| v.as_str()).unwrap_or(""),
                                "note": poc.get("note").and_then(|v| v.as_str()).unwrap_or(""),
                                "affected_versions": versions,
                                "vendor": &vendor,
                            }));
                        }
                        poc_items.sort_by(|a, b| {
                            let pa = a.get("public").and_then(|v| v.as_bool()).unwrap_or(false);
                            let pb = b.get("public").and_then(|v| v.as_bool()).unwrap_or(false);
                            pb.cmp(&pa)
                        });
                        groups.push(serde_json::json!({"product": product, "pocs": poc_items}));
                    }
                }
            }
        }
        groups.sort_by(|a, b| {
            let has_pub = |g: &serde_json::Value| g.get("pocs").and_then(|v| v.as_array()).map(|arr| arr.iter().any(|p| p.get("public").and_then(|v| v.as_bool()).unwrap_or(false))).unwrap_or(false);
            let pa = has_pub(a);
            let pb = has_pub(b);
            pb.cmp(&pa)
        });
        groups
    };

    // POC running statuses
    let poc_running: Vec<serde_json::Value> = {
        let mut statuses = Vec::new();
        if let Ok(mut procs) = state.poc_processes.lock() {
            for (id, info) in procs.iter_mut() {
                let elapsed = info.start_time.elapsed().as_secs();
                let status = match info.child.try_wait() {
                    Ok(Some(_)) => "finished",
                    Ok(None) => "running",
                    Err(_) => "error",
                };
                statuses.push(serde_json::json!({
                    "poc_id": id,
                    "poc_name": info.poc_name,
                    "status": status,
                    "elapsed_secs": elapsed,
                }));
            }
        }
        statuses
    };

    // Sysinfo
    let sysinfo_data = {
        let mut sys = state.sys.lock().unwrap();
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        serde_json::json!({
            "hostname": state.hostname,
            "cpu_usage": sys.global_cpu_usage(),
            "memory_used_mb": sys.used_memory() / 1024 / 1024,
            "memory_total_mb": sys.total_memory() / 1024 / 1024,
            "uptime_secs": System::uptime(),
        })
    };

    let running = state.dispatching.load(Ordering::Relaxed);
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let data = serde_json::json!({
        "generated_at": now,
        "refresh_interval": "2 minutes",
        "dispatching": running,
        "cluster": {
            "total_nodes": state.nodes.len(),
            "online_nodes": online_count,
            "total_speed": total_speed,
            "total_scanned": state.total_scanned.load(Ordering::Relaxed),
            "total_hits": state.total_hits.load(Ordering::Relaxed),
            "pending_tasks": pending,
            "assigned_tasks": assigned,
            "completed_tasks": completed,
        },
        "nodes": nodes_info,
        "recent_hits": hits,
        "stats": { "by_poc": by_poc, "by_node": by_node },
        "poc_progress": poc_progress,
        "poc_list": poc_list,
        "poc_running": poc_running,
        "sysinfo": sysinfo_data,
    });

    serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".to_string())
}

async fn serve_scanner_page() -> Html<&'static str> {
    Html(SCANNER_HTML)
}

async fn serve_bench_page() -> Html<&'static str> {
    Html(crate::BENCH_HTML)
}

async fn serve_results_page() -> Html<&'static str> {
    Html(crate::RESULTS_HTML)
}

async fn serve_stats_page() -> Html<&'static str> {
    Html(crate::STATS_HTML)
}

async fn serve_pocs_page() -> Html<&'static str> {
    Html(crate::POCS_HTML)
}

async fn serve_about_page() -> Html<&'static str> {
    Html(crate::ABOUT_HTML)
}

// === Panel API handlers (cluster-adapted) ===

async fn api_status(state: Arc<MasterState>) -> Json<serde_json::Value> {
    let queue = state.task_queue.lock().await;
    let pending = queue.pending.len();
    drop(queue);

    let mut total_speed = 0.0;
    let online = state.nodes.iter().filter(|e| e.value().online).count();
    for entry in state.nodes.iter() {
        total_speed += entry.value().speed;
    }

    let dispatching = state.dispatching.load(Ordering::Relaxed);
    let running = dispatching && online > 0;
    let elapsed = state.start_time.elapsed().as_secs_f64();
    let mqs = state.max_queue_size.load(Ordering::Relaxed);
    let mqs_display = if mqs == u64::MAX { 0u64 } else { mqs };

    Json(serde_json::json!({
        "running": running,
        "dispatching": dispatching,
        "status": if running { "running" } else { "idle" },
        "total_mnemonics": state.total_scanned.load(Ordering::Relaxed),
        "speed_mps": format!("{:.0}", total_speed),
        "total_hits": state.total_hits.load(Ordering::Relaxed),
        "elapsed_seconds": elapsed,
        "utxo_set_size": 56598777_u64,
        "threads": state.nodes.len(),
        "pending_tasks": pending,
        "pending_files": pending,
        "pending_by_dir": {},
        "current_file": format!("{} nodes active", online),
        "paths": "distributed",
        "depth": state.depth,
        "addrs_per_mnemonic": state.depth * 4,
        "gpu_available": true,
        "use_gpu": true,
        "gpu_name": "Cluster Mode",
        "bench_running": state.bench_running.load(Ordering::Relaxed),
        "max_queue_size": mqs_display,
    }))
}

async fn api_sysinfo(state: Arc<MasterState>) -> Json<serde_json::Value> {
    let (cpu_usage, mem_used_mb) = {
        let mut sys = state.sys.lock().unwrap();
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        let cpu = sys.global_cpu_usage();
        let mem = sys.used_memory() / 1024 / 1024;
        (cpu, mem)
    };

    let uptime_secs = state.start_time.elapsed().as_secs();

    Json(serde_json::json!({
        "hostname": state.hostname,
        "cpu_name": state.cpu_name,
        "cpu_cores": state.sys.lock().unwrap().cpus().len(),
        "cpu_usage": cpu_usage as u64,
        "used_memory_mb": mem_used_mb,
        "total_memory_mb": state.total_memory_mb,
        "mem_used_mb": mem_used_mb,
        "mem_total_mb": state.total_memory_mb,
        "uptime_secs": uptime_secs,
        "gpu_name": "Cluster Mode",
        "gpu_util": 0,
        "gpu_mem_used_mb": 0,
        "gpu_mem_total_mb": 0,
        "gpu_temp_c": null,
    }))
}

async fn api_results(state: Arc<MasterState>) -> Json<serde_json::Value> {
    let (results, total_count): (Vec<serde_json::Value>, u64) = {
        let db = state.db.lock().unwrap();
        let count: u64 = db.query_row("SELECT COUNT(*) FROM hits", [], |row| row.get(0)).unwrap_or(0);
        let mut stmt = match db.prepare(
            "SELECT source, address, discovered_at, node_id, COALESCE(poc_id,'') FROM hits ORDER BY id DESC LIMIT 200"
        ) {
            Ok(s) => s,
            Err(_) => return Json(serde_json::json!({"count": 0, "results": []})),
        };
        let rows: Vec<serde_json::Value> = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "source": row.get::<_, String>(0).unwrap_or_default(),
                "address": row.get::<_, String>(1).unwrap_or_default(),
                "found_at": row.get::<_, String>(2).unwrap_or_default(),
                "node_id": row.get::<_, String>(3).unwrap_or_default(),
                "poc_id": row.get::<_, String>(4).unwrap_or_default(),
            }))
        }).unwrap().flatten().collect();
        (rows, count)
    };
    Json(serde_json::json!({"count": total_count, "results": results}))
}

async fn api_dir_stats(state: Arc<MasterState>) -> Json<serde_json::Value> {
    let db = state.db.lock().unwrap();
    let mut map = HashMap::new();
    if let Ok(mut stmt) = db.prepare(
        "SELECT t.poc_id, SUM(t.scanned_count), COUNT(*), MAX(t.completed_at), COALESCE(hc.cnt,0) \
         FROM task_log t \
         LEFT JOIN (SELECT COALESCE(poc_id,'') as pid, COUNT(*) as cnt FROM hits GROUP BY pid) hc ON hc.pid=t.poc_id \
         GROUP BY t.poc_id"
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0).unwrap_or_default(),
                row.get::<_, u64>(1).unwrap_or(0),
                row.get::<_, u64>(2).unwrap_or(0),
                row.get::<_, String>(3).unwrap_or_default(),
                row.get::<_, u64>(4).unwrap_or(0),
            ))
        }) {
            for r in rows.flatten() {
                map.insert(r.0.clone(), serde_json::json!({
                    "files_processed": r.2,
                    "mnemonics_scanned": r.1,
                    "privkeys_scanned": 0,
                    "hits": r.4,
                    "last_file": "-",
                    "last_time": r.3,
                }));
            }
        }
    }
    let mut node_stats: Vec<serde_json::Value> = Vec::new();
    if let Ok(mut stmt) = db.prepare(
        "SELECT t.node_id, t.poc_id, SUM(t.scanned_count), COUNT(*), MAX(t.completed_at), \
         (SELECT COUNT(*) FROM hits h WHERE h.node_id=t.node_id AND COALESCE(h.poc_id,'')=t.poc_id) \
         FROM task_log t GROUP BY t.node_id, t.poc_id ORDER BY t.node_id, t.poc_id"
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "node_id": row.get::<_, String>(0).unwrap_or_default(),
                "poc_id": row.get::<_, String>(1).unwrap_or_default(),
                "scanned": row.get::<_, u64>(2).unwrap_or(0),
                "hits": row.get::<_, u64>(5).unwrap_or(0),
                "tasks": row.get::<_, u64>(3).unwrap_or(0),
                "last_time": row.get::<_, String>(4).unwrap_or_default(),
            }))
        }) {
            node_stats = rows.flatten().collect();
        }
    }
    Json(serde_json::json!({"by_poc": map, "by_node": node_stats}))
}

async fn api_pocs_list(state: Arc<MasterState>) -> Json<serde_json::Value> {
    let pocinfo_path = state.poc_base_dir.join("pocinfo.json");
    let pocs = if let Ok(content) = fs::read_to_string(&pocinfo_path) {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
            let mut groups = Vec::new();
            if let Some(vendors) = data.as_object() {
                for (_vk, vd) in vendors {
                    let product = vd.get("product").and_then(|v| v.as_str()).unwrap_or(_vk).to_string();
                    let vendor = vd.get("vendor").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let mut poc_items = Vec::new();
                    let items: Vec<&serde_json::Value> = vd.get("pocs").and_then(|p| p.as_array()).into_iter().flatten().collect();
                    for poc in items {
                        let id = poc.get("id").and_then(|v| v.as_str()).unwrap_or("");
                        let name = poc.get("name").or_else(|| poc.get("title")).and_then(|v| v.as_str()).unwrap_or("");
                        let versions = match poc.get("affected_versions") {
                            Some(v) if v.is_array() => v.clone(),
                            Some(v) if v.is_string() => serde_json::json!([v.as_str().unwrap_or("")]),
                            _ => serde_json::json!([]),
                        };
                        let has_gen = if !id.is_empty() {
                            state.poc_base_dir.join("targets").read_dir().ok()
                                .and_then(|dirs| { for d in dirs.filter_map(|e| e.ok()) { if d.path().join(id).join("generator.py").is_file() { return Some(true); } } None })
                                .unwrap_or(false)
                        } else { false };
                        poc_items.push(serde_json::json!({
                            "id": id, "name": name,
                            "output_type": poc.get("output_type").and_then(|v| v.as_str()).unwrap_or("unknown"),
                            "affected_versions": versions,
                            "severity": poc.get("severity").or(poc.get("risk_level")).and_then(|v| v.as_str()).unwrap_or(""),
                            "disclosure_status": poc.get("disclosure_status").and_then(|v| v.as_str()).unwrap_or(""),
                            "public": poc.get("public").and_then(|v| v.as_bool()).unwrap_or(false),
                            "is_fixed": poc.get("is_fixed").and_then(|v| v.as_bool()).unwrap_or(false),
                            "has_generator": has_gen,
                            "generation_speed": poc.get("generation_speed").and_then(|v| v.as_str()).unwrap_or(""),
                            "coverage_time_range": poc.get("coverage_time_range").and_then(|v| v.as_str()).unwrap_or(""),
                            "note": poc.get("note").and_then(|v| v.as_str()).unwrap_or(""),
                            "vendor": &vendor,
                        }));
                    }
                    groups.push(serde_json::json!({"product": product, "pocs": poc_items}));
                }
            }
            serde_json::json!({"groups": groups})
        } else { serde_json::json!({"groups": [], "error": "parse error"}) }
    } else { serde_json::json!({"groups": [], "error": "pocinfo.json not found"}) };
    Json(pocs)
}

async fn api_pocs_status(state: Arc<MasterState>) -> Json<serde_json::Value> {
    let mut statuses = Vec::new();
    let mut finished_ids = Vec::new();

    if let Ok(mut procs) = state.poc_processes.lock() {
        for (id, info) in procs.iter_mut() {
            let elapsed = info.start_time.elapsed().as_secs();
            match info.child.try_wait() {
                Ok(Some(_)) => {
                    finished_ids.push(id.clone());
                    statuses.push(serde_json::json!({
                        "poc_id": id,
                        "poc_name": info.poc_name,
                        "status": "finished",
                        "elapsed_secs": elapsed,
                        "output_dir": info.output_dir,
                    }));
                }
                Ok(None) => {
                    statuses.push(serde_json::json!({
                        "poc_id": id,
                        "poc_name": info.poc_name,
                        "status": "running",
                        "elapsed_secs": elapsed,
                        "output_dir": info.output_dir,
                    }));
                }
                Err(_) => {
                    finished_ids.push(id.clone());
                    statuses.push(serde_json::json!({
                        "poc_id": id,
                        "poc_name": info.poc_name,
                        "status": "error",
                        "elapsed_secs": elapsed,
                        "output_dir": info.output_dir,
                    }));
                }
            }
        }
        for id in finished_ids {
            procs.remove(&id);
        }
    }

    let running_count = statuses.iter().filter(|s| s.get("status").and_then(|v| v.as_str()) == Some("running")).count();
    let mc = *state.poc_max_concurrent.lock().unwrap();
    let mf = *state.poc_maxfile.lock().unwrap();

    // Load progress from master.db
    let all_progress = {
        let db = state.db.lock().unwrap();
        let mut map = serde_json::Map::new();
        if let Ok(mut stmt) = db.prepare("SELECT poc_id, current_index, batch_num, total_generated, total_space, updated_at FROM poc_progress") {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0).unwrap_or_default(),
                    row.get::<_, i64>(1).unwrap_or(0),
                    row.get::<_, i64>(2).unwrap_or(0),
                    row.get::<_, i64>(3).unwrap_or(0),
                    row.get::<_, i64>(4).unwrap_or(0),
                    row.get::<_, String>(5).unwrap_or_default(),
                ))
            }) {
                for r in rows.flatten() {
                    map.insert(r.0.clone(), serde_json::json!({
                        "current_index": r.1,
                        "batch_num": r.2,
                        "total_generated": r.3,
                        "total_space": r.4,
                        "timestamp": r.5,
                    }));
                }
            }
        }
        serde_json::Value::Object(map)
    };

    Json(serde_json::json!({
        "running_count": running_count,
        "max_concurrent": mc,
        "maxfile": mf,
        "pocs": statuses,
        "all_progress": all_progress,
    }))
}

async fn api_pocs_log(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let poc_id = parsed.get("poc_id").and_then(|v| v.as_str()).unwrap_or("");
    if poc_id.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "missing poc_id"}));
    }

    let is_running = state.poc_processes.lock().ok()
        .map(|procs| procs.contains_key(poc_id))
        .unwrap_or(false);

    let log_content = {
        let db = state.db.lock().unwrap();
        let mut lines = Vec::new();
        if let Ok(mut stmt) = db.prepare("SELECT line FROM poc_logs WHERE poc_id=? ORDER BY id DESC LIMIT 100") {
            if let Ok(rows) = stmt.query_map([poc_id], |row| row.get::<_, String>(0)) {
                for line in rows.flatten() {
                    lines.push(line);
                }
            }
        }
        lines.reverse();
        if lines.is_empty() { "(no logs yet)".to_string() } else { lines.join("\n") }
    };

    Json(serde_json::json!({"ok": true, "poc_id": poc_id, "log": log_content, "is_running": is_running}))
}

async fn api_pocs_reload(state: Arc<MasterState>) -> Json<serde_json::Value> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    *state.last_reload_time.lock().unwrap() = Some(now.clone());
    *state.reload_reason.lock().unwrap() = Some("manual".to_string());
    Json(serde_json::json!({"ok": true, "time": now}))
}

async fn api_pocs_reload_info(state: Arc<MasterState>) -> Json<serde_json::Value> {
    let t = state.last_reload_time.lock().unwrap().clone();
    let r = state.reload_reason.lock().unwrap().clone();
    Json(serde_json::json!({
        "last_reload_time": t,
        "reload_reason": r,
    }))
}

async fn api_pocs_settings(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    if let Some(mc) = parsed.get("max_concurrent").and_then(|v| v.as_u64()) {
        *state.poc_max_concurrent.lock().unwrap() = mc as usize;
    }
    if let Some(mf) = parsed.get("maxfile").and_then(|v| v.as_u64()) {
        *state.poc_maxfile.lock().unwrap() = mf as u32;
    }
    Json(serde_json::json!({"ok": true}))
}

async fn api_pocs_edit_progress(_state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let _poc_id = parsed.get("poc_id").and_then(|v| v.as_str()).unwrap_or("");
    Json(serde_json::json!({"ok": true}))
}

async fn api_bench_run(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    if state.bench_running.load(Ordering::Relaxed) {
        return Json(serde_json::json!({"ok": false, "error": "already running"}));
    }

    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let input_type = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("mnemonic").to_string();
    let content = parsed.get("content").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let node_id = parsed.get("node_id").and_then(|v| v.as_str()).unwrap_or("").to_string();

    if content.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "Input is empty"}));
    }
    if node_id.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "No node selected"}));
    }

    // Verify node exists and is online
    let node_online = state.nodes.get(&node_id).map(|n| n.online).unwrap_or(false);
    if !node_online {
        return Json(serde_json::json!({"ok": false, "error": "Selected node is offline"}));
    }

    // Verify node is paused (not enabled for task dispatch)
    let node_enabled = state.enabled_nodes.lock().unwrap().contains(&node_id);
    if node_enabled {
        return Json(serde_json::json!({"ok": false, "error": "Node is currently running tasks. Pause it first."}));
    }

    let lines: Vec<String> = content.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let bench_id = uuid::Uuid::new_v4().to_string()[..8].to_string();

    state.bench_running.store(true, Ordering::Relaxed);
    state.bench_done.store(false, Ordering::Relaxed);
    state.bench_log.lock().unwrap().clear();

    {
        let mut log = state.bench_log.lock().unwrap();
        log.push("=== Benchmark Test (Node Execution) ===".to_string());
        log.push(format!("Node: {}", node_id));
        log.push(format!("Type: {}, Lines: {}, Depth: {}", input_type, lines.len(), state.depth));
        log.push(format!("Bench ID: {}", bench_id));
        log.push("Dispatching to node... waiting for results".to_string());
    }

    // Queue the bench task for the node (delivered via heartbeat)
    let bench_task = crate::protocol::BenchTask {
        bench_id,
        input_type,
        lines,
        depth: state.depth,
    };
    state.bench_task_queue.lock().unwrap().insert(node_id, bench_task);

    // Timeout: if no result in 120s, mark done with timeout message
    let timeout_state = state.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(120)).await;
        if timeout_state.bench_running.load(Ordering::Relaxed) {
            timeout_state.bench_log.lock().unwrap().push("[Bench] Timeout: node did not respond within 120s".to_string());
            timeout_state.bench_done.store(true, Ordering::Relaxed);
            timeout_state.bench_running.store(false, Ordering::Relaxed);
        }
    });

    Json(serde_json::json!({"ok": true}))
}

async fn api_bench_log(state: Arc<MasterState>) -> Json<serde_json::Value> {
    let log = state.bench_log.lock().unwrap().clone();
    let done = state.bench_done.load(Ordering::Relaxed);
    Json(serde_json::json!({
        "lines": log,
        "done": done,
        "running": state.bench_running.load(Ordering::Relaxed),
    }))
}

async fn api_bench_result(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let req: crate::protocol::BenchResultRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return Json(serde_json::json!({"ok": false, "error": format!("parse error: {}", e)})),
    };

    let mut log = state.bench_log.lock().unwrap();
    log.push(String::new());
    log.push(format!("=== Results from node {} (bench {}) ===", req.node_id, req.bench_id));

    for rl in &req.results {
        log.push(format!("[Input] \"{}\"", rl.input));
        for d in &rl.derived {
            let mark = if d.hit { " *** HIT ***" } else { "" };
            log.push(format!("  {} -> {}{}", d.path, d.address, mark));
        }
        log.push(String::new());
    }

    log.push("[Bench] Done.".to_string());
    drop(log);

    state.bench_done.store(true, Ordering::Relaxed);
    state.bench_running.store(false, Ordering::Relaxed);

    Json(serde_json::json!({"ok": true}))
}

fn api_convert(body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let input_type = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("mnemonic");
    let content = parsed.get("content").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let depth: u32 = parsed.get("depth").and_then(|v| v.as_u64()).unwrap_or(3) as u32;

    if content.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "Content is empty"}));
    }

    match input_type {
        "mnemonic" => {
            match crate::derive::derive_privkeys_from_mnemonic(&content, depth) {
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
            match crate::derive_from_private_key(&content) {
                Ok(addrs) => {
                    let items: Vec<serde_json::Value> = addrs.iter().map(|(label, addr)| {
                        serde_json::json!({"path": label, "address": addr})
                    }).collect();
                    Json(serde_json::json!({"ok": true, "type": "privkey", "results": items}))
                }
                Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
            }
        }
        _ => Json(serde_json::json!({"ok": false, "error": "Unknown type"})),
    }
}

async fn api_start(state: Arc<MasterState>, _body: String) -> Json<serde_json::Value> {
    state.dispatching.store(true, Ordering::Relaxed);
    let pending = state.task_queue.lock().await.pending.len();
    println!("[Master] Dispatching STARTED ({} tasks pending)", pending);
    Json(serde_json::json!({"ok": true, "dispatching": true, "pending_tasks": pending}))
}

async fn api_stop(state: Arc<MasterState>) -> Json<serde_json::Value> {
    state.dispatching.store(false, Ordering::Relaxed);
    println!("[Master] Dispatching STOPPED");
    Json(serde_json::json!({"ok": true, "dispatching": false}))
}

async fn api_export_now(state: Arc<MasterState>) -> Json<serde_json::Value> {
    let export_path = state.scanner_folder.join("all.json");
    let tuomin_path = state.scanner_folder.join("tuomin_all.json");
    let json = build_export_json(&state).await;
    let tmp_path = export_path.with_extension("json.tmp");
    if let Ok(()) = fs::write(&tmp_path, json.as_bytes()) {
        let _ = fs::rename(&tmp_path, &export_path);
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&json) {
            let masked = build_tuomin_json(&data);
            let tmp2 = tuomin_path.with_extension("json.tmp");
            if let Ok(()) = fs::write(&tmp2, masked.as_bytes()) {
                let _ = fs::rename(&tmp2, &tuomin_path);
            }
        }
        println!("[Export] all.json + tuomin_all.json generated on demand");
        Json(serde_json::json!({"ok": true}))
    } else {
        Json(serde_json::json!({"ok": false, "error": "Failed to write all.json"}))
    }
}

async fn api_nodes_enable(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    
    // Single node toggle: {node_id: "xxx", enabled: true/false}
    if let Some(node_id) = parsed.get("node_id").and_then(|v| v.as_str()) {
        let enabled = parsed.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        let mut set = state.enabled_nodes.lock().unwrap();
        if enabled {
            set.insert(node_id.to_string());
        } else {
            set.remove(node_id);
        }
        return Json(serde_json::json!({"ok": true, "node_id": node_id, "enabled": enabled}));
    }
    
    // Batch: {node_ids: [...]}
    if let Some(nodes) = parsed.get("node_ids").and_then(|v| v.as_array()) {
        let ids: HashSet<String> = nodes.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        let count = ids.len();
        *state.enabled_nodes.lock().unwrap() = ids;
        Json(serde_json::json!({"ok": true, "enabled": count}))
    } else {
        state.enabled_nodes.lock().unwrap().clear();
        Json(serde_json::json!({"ok": true, "enabled": "all"}))
    }
}

async fn api_nodes_switch_mode(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
    let node_id = match parsed.get("node_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return Json(serde_json::json!({"ok": false, "error": "node_id required"})),
    };
    let target_mode = match parsed.get("mode").and_then(|v| v.as_str()) {
        Some(m) if m == "gpu" || m == "cpu" => m.to_string(),
        _ => return Json(serde_json::json!({"ok": false, "error": "mode must be 'gpu' or 'cpu'"})),
    };

    // Validate: check if node exists and is online
    let node_info = match state.nodes.get(&node_id) {
        Some(n) => (n.online, n.gpu_available, n.gpu_error.clone(), n.compute_mode.clone()),
        None => return Json(serde_json::json!({"ok": false, "error": "node not found"})),
    };

    if !node_info.0 {
        return Json(serde_json::json!({"ok": false, "error": "node is offline"}));
    }

    // If switching to GPU, check if GPU is available on that node
    if target_mode == "gpu" && !node_info.1 {
        let reason = if node_info.2.is_empty() { "GPU not available".to_string() } else { node_info.2 };
        return Json(serde_json::json!({"ok": false, "error": reason}));
    }

    // Already in target mode?
    if node_info.3 == target_mode {
        return Json(serde_json::json!({"ok": true, "message": "already in this mode"}));
    }

    // Queue the switch command (delivered via next heartbeat)
    state.mode_switch_queue.lock().unwrap().insert(node_id.clone(), target_mode.clone());
    println!("[Master] Queued mode switch for {}: -> {}", &node_id[..node_id.len().min(8)], target_mode);
    Json(serde_json::json!({"ok": true, "message": "switch command queued"}))
}

async fn api_set_queue_limit(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let limit = parsed.get("limit").and_then(|v| v.as_u64()).unwrap_or(0);
    if limit == 0 {
        state.max_queue_size.store(u64::MAX, Ordering::Relaxed);
        println!("[Master] Global queue limit set to unlimited");
    } else {
        state.max_queue_size.store(limit, Ordering::Relaxed);
        println!("[Master] Global queue limit set to {}", limit);
    }
    Json(serde_json::json!({"ok": true, "limit": limit}))
}

async fn api_set_node_limit(state: Arc<MasterState>, body: String) -> Json<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let node_id = parsed.get("node_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let limit = parsed.get("limit").and_then(|v| v.as_u64()).unwrap_or(0);
    if node_id.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "node_id required"}));
    }
    state.node_task_limits.lock().unwrap().insert(node_id.clone(), limit);
    println!("[Master] Node {} task limit set to {} (0=unlimited)", &node_id[..node_id.len().min(8)], limit);
    Json(serde_json::json!({"ok": true, "node_id": node_id, "limit": limit}))
}

const SCANNER_HTML: &str = r##"<!DOCTYPE html><html><head><meta charset="utf-8"><title>easyWallet - Cluster</title>
<style>
:root{--bg:#f8f9fa;--card:#fff;--border:#e2e8f0;--accent:#0066ff;--green:#16a34a;--red:#dc2626;--orange:#ea580c;--text:#1a1a2e;--muted:#64748b}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.layout{max-width:1100px;margin:0 auto;padding:20px}
header{display:flex;align-items:center;justify-content:space-between;padding:16px 0;border-bottom:1px solid var(--border);margin-bottom:20px}
header h1{font-size:18px;color:var(--text);font-weight:700}
nav{display:flex;gap:2px;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:3px}
nav a{padding:7px 14px;border-radius:6px;font-size:13px;color:var(--muted);text-decoration:none;transition:all .15s;font-weight:500}
nav a:hover{color:var(--text);background:#f1f5f9}
nav a.active{color:#fff;background:var(--accent);font-weight:600}
.sys-bar{display:flex;gap:16px;padding:10px 16px;background:var(--card);border-radius:8px;margin-bottom:12px;border:1px solid var(--border);flex-wrap:wrap;align-items:center;font-size:12px;color:var(--muted)}
.sys-bar .sys-item{display:flex;align-items:center;gap:6px}
.sys-bar .sys-label{font-weight:500;color:var(--muted);white-space:nowrap}
.sys-bar .sys-val{font-weight:700;color:var(--text);font-variant-numeric:tabular-nums;min-width:3em;white-space:nowrap}
.sys-bar .meter{width:60px;height:6px;background:#e2e8f0;border-radius:3px;overflow:hidden;display:inline-block;flex-shrink:0}
.sys-bar .meter-fill{height:100%;border-radius:3px;transition:width .5s}
.fill-ok{background:var(--green)}.fill-warn{background:var(--orange)}.fill-danger{background:var(--red)}
.toolbar{display:flex;align-items:center;gap:16px;padding:14px 18px;background:var(--card);border-radius:10px;margin-bottom:16px;border:1px solid var(--border);flex-wrap:wrap}
.btn{padding:8px 20px;border:none;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;transition:all .15s}
.btn-start{background:var(--green);color:#fff}.btn-start:hover{filter:brightness(1.1)}
.btn-stop{background:var(--red);color:#fff}.btn-stop:hover{filter:brightness(1.1)}
.btn:disabled{opacity:0.3;cursor:not-allowed}
.status-pill{font-size:12px;padding:4px 12px;border-radius:20px;font-weight:500}
.status-idle{background:#f1f5f9;color:var(--muted)}
.status-running{background:#dcfce7;color:var(--green)}
.divider{width:1px;height:28px;background:var(--border)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
@media(max-width:700px){.grid{grid-template-columns:repeat(2,1fr)}}
.card{background:var(--card);border-radius:10px;padding:16px;border:1px solid var(--border)}
.card .val{font-size:22px;font-weight:700;color:var(--text);margin-bottom:4px}
.card .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.section-title{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin:20px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.table-wrap{background:var(--card);border-radius:10px;border:1px solid var(--border);overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
thead{background:#f1f5f9}
th{padding:10px 12px;text-align:left;font-weight:600;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border)}
td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover{background:#f8fafc}
.st-on{color:var(--green);font-weight:600}
.st-off{color:var(--red);font-weight:600}
.node-btn{padding:4px 10px;border:none;border-radius:4px;font-size:10px;font-weight:600;cursor:pointer;transition:all .15s;white-space:nowrap}
.btn-start{background:#dcfce7;color:var(--green);border:1px solid #bbf7d0}
.btn-pause{background:#fef2f2;color:var(--red);border:1px solid #fecaca}
.btn-gpu{background:#dbeafe;color:#2563eb;border:1px solid #bfdbfe}
.btn-cpu{background:#f3e8ff;color:#7c3aed;border:1px solid #e9d5ff}
.btn-disabled{background:#f1f5f9;color:#94a3b8;border:1px solid #e2e8f0;cursor:not-allowed;opacity:0.6}
.node-btn:hover:not(.btn-disabled){filter:brightness(0.92)}
.actions-cell{display:flex;gap:4px;align-items:center}
</style></head><body>
<div class="layout">
<header>
<h1>easyWallet</h1>
<nav>
<a class="active" href="/">Scanner</a>
<a href="/bench">Benchmark</a>
<a href="/results">Hit Records</a>
<a href="/stats">Stats</a>
<a href="/pocs">POC Test</a>
<a href="/about">Must Read</a></nav>
<button onclick="toggleLang()" style="padding:4px 10px;border:1px solid var(--border);border-radius:4px;background:var(--card);font-size:12px;cursor:pointer;color:var(--muted);margin-left:8px" id="langBtn">中文</button>
</header>
<div class="sys-bar">
<span class="sys-item"><span class="sys-label">Master:</span><span class="sys-val" id="sHost">-</span></span>
<span class="sys-item"><span class="sys-label">CPU:</span><span class="sys-val" id="sCpu">-</span></span>
<span class="sys-item"><span class="sys-val" id="sCpuPct">0%</span><span class="meter"><span class="meter-fill fill-ok" id="sCpuBar" style="width:0%"></span></span></span>
<span class="sys-item"><span class="sys-label">RAM:</span><span class="sys-val" id="sMem">-</span><span class="meter"><span class="meter-fill fill-ok" id="sMemBar" style="width:0%"></span></span></span>
<span class="sys-item"><span class="sys-label">Uptime:</span><span class="sys-val" id="sUptime">-</span></span>
</div>
<div class="toolbar">
<button class="btn btn-start" id="btnStart" onclick="doStart()">Start Dispatch</button>
<button class="btn btn-stop" id="btnStop" onclick="doStop()" disabled>Stop Dispatch</button>
<button class="btn" style="background:#6366f1;color:#fff;margin-left:8px" onclick="doExport()">Export all.json</button>
<span class="status-pill status-idle" id="statusPill">Idle</span>
<div class="divider"></div>
<span style="font-size:12px;color:var(--muted);display:inline-flex;align-items:center;gap:6px" data-i18n="queue_limit_label">Limit:</span>
<input id="queueLimitInput" type="text" inputmode="numeric" value="500" style="width:70px;padding:4px 8px;border:1px solid var(--border);border-radius:4px;font-size:12px;text-align:center">
<button class="btn" style="background:var(--accent);color:#fff;padding:4px 12px;font-size:11px" onclick="setQueueLimit()" data-i18n="apply_btn">Set</button>
<div class="divider"></div>
<span style="font-size:12px;color:var(--muted)" data-i18n="toolbar_hint">Set to 0 for unlimited. Otherwise limits the queued task count to control resource usage.</span>
</div>
<div class="grid">
<div class="card"><div class="val" id="vSpeed">0</div><div class="lbl">Speed (m/s)</div></div>
<div class="card"><div class="val" id="vScanned">0</div><div class="lbl">Scanned</div></div>
<div class="card"><div class="val" id="vHits">0</div><div class="lbl">Hits</div></div>
<div class="card"><div class="val" id="vNodes">0</div><div class="lbl">Nodes Online</div></div>
<div class="card"><div class="val" id="vPending">0</div><div class="lbl">Pending Tasks</div></div>
<div class="card"><div class="val" id="vCompleted">0</div><div class="lbl">Completed</div></div>
</div>
<div class="section-title">Nodes</div>
<div class="table-wrap">
<table>
<thead><tr><th>Node</th><th>Hostname</th><th>CPU</th><th>GPU</th><th>GPU%</th><th>VRAM</th><th>Temp</th><th>Speed</th><th>Scanned</th><th>Hits</th><th>CPU%</th><th>RAM</th><th>Status</th><th>Actions</th></tr></thead>
<tbody id="nodeBody"><tr><td colspan="14" style="text-align:center;color:var(--muted);padding:40px">Waiting for nodes to connect...</td></tr></tbody>
</table>
</div>
</div>
<script>
let dispatching=false;
function mc(p){return p>85?'fill-danger':p>60?'fill-warn':'fill-ok'}
function fn(n){return n>=1e6?(n/1e6).toFixed(2)+'M':n>=1e3?(n/1e3).toFixed(1)+'K':String(n)}
async function refresh(){
  try{
    const d=await(await fetch('/api/status')).json();
    dispatching=d.dispatching||false;
    document.getElementById('statusPill').textContent=dispatching?'Dispatching':'Idle';
    document.getElementById('statusPill').className='status-pill '+(dispatching?'status-running':'status-idle');
    document.getElementById('btnStart').disabled=dispatching;
    document.getElementById('btnStop').disabled=!dispatching;
    document.getElementById('vSpeed').textContent=d.speed_mps||'0';
    document.getElementById('vScanned').textContent=fn(Number(d.total_mnemonics||0));
    document.getElementById('vHits').textContent=d.total_hits||0;
    document.getElementById('vPending').textContent=d.pending_tasks||0;
    if(d.max_queue_size!=null){const ql=document.getElementById('queueLimitInput');if(document.activeElement!==ql)ql.value=d.max_queue_size;}
  }catch(e){}
  try{
    const s=await(await fetch('/api/sysinfo')).json();
    document.getElementById('sHost').textContent=s.hostname||'-';
    document.getElementById('sCpu').textContent=s.cpu_name||'-';
    const cp=Math.round(s.cpu_usage||0);
    document.getElementById('sCpuPct').textContent=cp+'%';
    document.getElementById('sCpuBar').style.width=cp+'%';
    document.getElementById('sCpuBar').className='meter-fill '+mc(cp);
    const mp=s.total_memory_mb>0?Math.round((s.used_memory_mb||0)/s.total_memory_mb*100):0;
    document.getElementById('sMem').textContent=(s.used_memory_mb||0)+'/'+(s.total_memory_mb||0)+' MB';
    document.getElementById('sMemBar').style.width=mp+'%';
    document.getElementById('sMemBar').className='meter-fill '+mc(mp);
    if(s.uptime_secs){const h=Math.floor(s.uptime_secs/3600),m=Math.floor((s.uptime_secs%3600)/60);document.getElementById('sUptime').textContent=h+'h '+m+'m';}
  }catch(e){}
  try{
    const c=await(await fetch('/api/cluster/status')).json();
    const nodes=c.nodes||[];
    document.getElementById('vNodes').textContent=nodes.filter(n=>n.status==='online').length;
    document.getElementById('vCompleted').textContent=fn(c.completed_tasks||0);
    const body=document.getElementById('nodeBody');
    const ae=document.activeElement;
    if(ae&&ae.id&&ae.id.startsWith('nlim_'))return;
    if(!nodes.length){body.innerHTML='<tr><td colspan="14" style="text-align:center;color:var(--muted);padding:40px">Waiting for nodes to connect...</td></tr>';return;}
    let h='';
    for(const n of nodes){
      const cls=n.status==='online'?'st-on':'st-off';
      const ago=n.last_heartbeat_secs_ago!=null?(n.last_heartbeat_secs_ago<60?Math.round(n.last_heartbeat_secs_ago)+'s':Math.round(n.last_heartbeat_secs_ago/60)+'m'):'?';
      const cp=n.cpu_usage!=null?Math.round(n.cpu_usage)+'%':'-';
      const mp=n.memory_usage!=null?Math.round(n.memory_usage)+'%':'-';
      const gpuPct=n.gpu_util!=null?Math.round(n.gpu_util)+'%':'-';
      const vram=n.gpu_mem_total_mb?(n.gpu_mem_used_mb||0)+'/'+(n.gpu_mem_total_mb)+'MB':'-';
      const temp=n.gpu_temp_c?n.gpu_temp_c+'°C':'-';
      const enabled=n.enabled!==false;
      const mode=n.compute_mode||'cpu';
      const canGpu=n.gpu_available;
      // Action buttons
      const toggleBtn=enabled
        ?`<button class="node-btn btn-pause" onclick="toggleNode('${n.node_id}',false)">Pause</button>`
        :`<button class="node-btn btn-start" onclick="toggleNode('${n.node_id}',true)">Start</button>`;
      let modeBtn='';
      const switching=modeSwitching[n.node_id];
      if(switching){
        modeBtn=`<button class="node-btn btn-disabled" disabled>Switching...</button>`;
      }else if(canGpu&&mode==='cpu'){
        modeBtn=enabled
          ?`<button class="node-btn btn-disabled" disabled title="Pause node first">Switch to GPU</button>`
          :`<button class="node-btn btn-gpu" onclick="switchMode('${n.node_id}','gpu')">Switch to GPU</button>`;
      }else if(canGpu&&mode==='gpu'){
        modeBtn=enabled
          ?`<button class="node-btn btn-disabled" disabled title="Pause node first">Switch to CPU</button>`
          :`<button class="node-btn btn-cpu" onclick="switchMode('${n.node_id}','cpu')">Switch to CPU</button>`;
      }else{
        modeBtn=`<button class="node-btn btn-disabled" title="${n.gpu_error||'No GPU'}" disabled>CPU only</button>`;
      }
      h+=`<tr>
        <td style="font-family:monospace;font-size:11px" title="${n.node_id}">${n.node_id.substring(0,8)}</td>
        <td>${n.hostname||'-'}</td>
        <td style="font-size:11px">${n.cpu_name||'-'}</td>
        <td style="font-size:11px">${n.gpu_name||'-'}</td>
        <td>${gpuPct}</td>
        <td style="font-size:11px">${vram}</td>
        <td>${temp}</td>
        <td style="font-weight:600">${n.benchmark_speed?n.benchmark_speed.toFixed(0):(n.speed?n.speed.toFixed(0):'-')}</td>
        <td>${fn(n.total_scanned||0)}</td>
        <td>${n.total_hits||0}</td>
        <td>${cp}</td>
        <td>${mp}</td>
        <td class="${cls}">${n.status} ${ago}</td>
        <td><div class="actions-cell">${toggleBtn}${modeBtn}<input type="text" inputmode="numeric" value="${n.task_limit||0}" style="width:40px;padding:2px 4px;border:1px solid var(--border);border-radius:4px;font-size:10px;text-align:center" id="nlim_${n.node_id}" title="Limit (0=∞)"><button class="node-btn" style="padding:2px 6px;font-size:10px;background:var(--accent);color:#fff;border:none;border-radius:3px" onclick="setNodeLimit('${n.node_id}')">Set</button></div></td>
      </tr>`;
    }
    body.innerHTML=h;
  }catch(e){}
}
async function toggleNode(id,en){
  await fetch('/api/nodes/enable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({node_id:id,enabled:en}),credentials:'same-origin'});
  refresh();
}
let modeSwitching={};
async function switchMode(id,mode){
  if(modeSwitching[id])return;
  modeSwitching[id]=true;
  refresh();
  const r=await(await fetch('/api/nodes/switch_mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({node_id:id,mode:mode}),credentials:'same-origin'})).json();
  if(!r.ok){alert('Cannot switch mode: '+(r.error||'unknown error'));modeSwitching[id]=false;refresh();return;}
  setTimeout(()=>{modeSwitching[id]=false;refresh();},5000);
}
async function doStart(){await fetch('/api/start',{method:'POST',credentials:'same-origin'});refresh();}
async function doStop(){await fetch('/api/stop',{method:'POST',credentials:'same-origin'});refresh();}
async function doExport(){const r=await fetch('/api/export',{method:'POST',credentials:'same-origin'});const d=await r.json();if(d.ok)alert('all.json exported successfully');else alert('Export failed: '+(d.error||'unknown'));}
async function setQueueLimit(){const v=parseInt(document.getElementById('queueLimitInput').value);if(isNaN(v)||v<0){alert('Invalid value');return;}const r=await(await fetch('/api/set_queue_limit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({limit:v}),credentials:'same-origin'})).json();if(!r.ok)alert('Failed: '+(r.error||'unknown'));else alert(curLang==='zh'?'设置成功，队列上限: '+v:'Success, limit: '+v);}
async function setNodeLimit(nodeId){const el=document.getElementById('nlim_'+nodeId);if(!el)return;const v=parseInt(el.value);if(isNaN(v)||v<0){alert('Invalid value');return;}const r=await(await fetch('/api/set_node_limit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({node_id:nodeId,limit:v}),credentials:'same-origin'})).json();if(!r.ok)alert('Failed: '+(r.error||'unknown'));else{alert(curLang==='zh'?'设置成功，节点上限: '+v:'Success, node limit: '+v);refresh();}}
refresh();setInterval(refresh,3000);
const I={en:{scanner:'Scanner',bench:'Benchmark',hits:'Hit Records',stats:'Stats',pocs:'POC Test',about:'Must Read',startBtn:'Start Dispatch',stopBtn:'Stop Dispatch',exportBtn:'Export all.json',idle:'Idle',dispatching:'Dispatching',speed:'Speed (m/s)',scanned:'Scanned',hitsLbl:'Hits',nodesOnline:'Nodes Online',pending:'Pending Tasks',completed:'Completed',nodes:'Nodes',waiting:'Waiting for nodes to connect...',master:'Master:',uptime:'Uptime:',gate:'Set to 0 for unlimited. Otherwise limits the queued task count to control resource usage.',pause:'Pause',start:'Start',switchGpu:'Switch to GPU',switchCpu:'Switch to CPU',switching:'Switching...',cpuOnly:'CPU only',pauseFirst:'Pause node first',langBtn:'中文',queueLimit:'Limit:',applyBtn:'Set',taskLimit:'Limit'},zh:{scanner:'扫描器',bench:'基准测试',hits:'命中记录',stats:'统计',pocs:'POC 测试',about:'必读',startBtn:'开始分发',stopBtn:'停止分发',exportBtn:'导出 all.json',idle:'空闲',dispatching:'任务分发中',speed:'速度 (m/s)',scanned:'已扫描',hitsLbl:'命中',nodesOnline:'在线节点',pending:'等待任务',completed:'已完成',nodes:'节点',waiting:'等待节点连接...',master:'主服务器:',uptime:'运行时间:',gate:'设为 0 表示无限制，设定数值后队列上限即为该值，可控制在跑任务量与资源消耗',pause:'暂停',start:'启动',switchGpu:'切换到 GPU',switchCpu:'切换到 CPU',switching:'切换中...',cpuOnly:'仅 CPU',pauseFirst:'请先暂停节点',langBtn:'English',queueLimit:'上限:',applyBtn:'Set',taskLimit:'上限'}};
let curLang=localStorage.getItem('dash_lang')||'en';
function applyLang(){const t=I[curLang];document.getElementById('langBtn').textContent=t.langBtn;const navs=document.querySelectorAll('nav a');const keys=['scanner','bench','hits','stats','pocs','about'];navs.forEach((a,i)=>{if(keys[i])a.textContent=t[keys[i]];});document.getElementById('btnStart').textContent=t.startBtn;document.getElementById('btnStop').textContent=t.stopBtn;document.querySelectorAll('.toolbar .btn')[2].textContent=t.exportBtn;const lbls=document.querySelectorAll('.card .lbl');const lk=['speed','scanned','hitsLbl','nodesOnline','pending','completed'];lbls.forEach((l,i)=>{if(lk[i])l.textContent=t[lk[i]];});document.querySelector('.section-title').textContent=t.nodes;const ql=document.querySelector('[data-i18n="queue_limit_label"]');if(ql)ql.textContent=t.queueLimit;const ab=document.querySelector('[data-i18n="apply_btn"]');if(ab)ab.textContent=t.applyBtn;const gateEl=document.querySelector('[data-i18n="toolbar_hint"]');if(gateEl)gateEl.textContent=t.gate;}
function toggleLang(){curLang=curLang==='en'?'zh':'en';localStorage.setItem('dash_lang',curLang);applyLang();}
applyLang();
</script></body></html>"##;
