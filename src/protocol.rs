use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub node_id: String,
    pub gpu_name: String,
    pub cpu_name: String,
    pub hostname: String,
    pub total_memory_mb: u64,
    pub benchmark_speed: f64,
    #[serde(default)]
    pub gpu_available: bool,
    #[serde(default)]
    pub gpu_error: String,
    #[serde(default = "default_compute_mode")]
    pub compute_mode: String, // "gpu" or "cpu"
}

fn default_compute_mode() -> String { "cpu".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub node_id: String,
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    pub speed: f64,
    pub total_scanned: u64,
    pub total_hits: u64,
    pub gpu_utilization: f32,
    pub current_task_id: Option<String>,
    #[serde(default)]
    pub cpu_usage: f64,
    #[serde(default)]
    pub memory_usage: f64,
    #[serde(default)]
    pub gpu_memory_used_mb: u64,
    #[serde(default)]
    pub gpu_memory_total_mb: u64,
    #[serde(default)]
    pub gpu_temp_c: u32,
    #[serde(default)]
    pub compute_mode: String, // "gpu" or "cpu"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub ok: bool,
    pub cancel_tasks: Vec<String>,
    #[serde(default)]
    pub switch_compute_mode: Option<String>, // "gpu" or "cpu" if master wants node to switch
    #[serde(default)]
    pub bench_task: Option<BenchTask>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchTask {
    pub bench_id: String,
    pub input_type: String, // "mnemonic" | "privkey" | "address"
    pub lines: Vec<String>,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchResultLine {
    pub input: String,
    pub derived: Vec<BenchDerived>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchDerived {
    pub path: String,
    pub address: String,
    pub hit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchResultRequest {
    pub node_id: String,
    pub bench_id: String,
    pub results: Vec<BenchResultLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPullRequest {
    pub node_id: String,
    pub preferred_batch_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPayload {
    pub task_id: String,
    pub poc_id: String,
    pub task_type: String, // "mnemonic" | "privkey"
    pub batch: Vec<String>,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPullResponse {
    pub task: Option<TaskPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitRecord {
    pub source: String,
    pub address: String,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultRequest {
    pub node_id: String,
    pub task_id: String,
    #[serde(default)]
    pub poc_id: String,
    pub scanned_count: u64,
    pub hits: Vec<HitRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultResponse {
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResultsRequest {
    pub node_id: String,
    pub results: Vec<TaskResultRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResultsResponse {
    pub ok: bool,
    pub accepted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node_id: String,
    pub gpu_name: String,
    pub hostname: String,
    pub speed: f64,
    pub total_scanned: u64,
    pub total_hits: u64,
    pub status: String, // "online" | "offline"
    pub last_heartbeat_secs_ago: f64,
    pub connected_since: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatus {
    pub total_nodes: usize,
    pub online_nodes: usize,
    pub total_speed: f64,
    pub total_scanned: u64,
    pub total_hits: u64,
    pub pending_tasks: usize,
    pub assigned_tasks: usize,
    pub completed_tasks: u64,
    pub nodes: Vec<NodeStatus>,
}
