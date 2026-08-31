//! CUDA GPU acceleration layer v2
//! Supports two modes:
//! 1. Full pipeline: PBKDF2 → BIP32 → secp256k1 → hash160 → filter match (all on GPU)
//! 2. Legacy: PBKDF2-only (GPU) + CPU derive (fallback)
//!
//! P1: Double-buffered CUDA stream pipeline — ping-pong streams overlap compute and transfer

use std::path::Path;
use std::sync::Arc;

use cudarc::driver::{CudaContext, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg};
use cudarc::nvrtc::Ptx;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CudaStatus {
    Available { device_count: u32 },
    Unavailable,
}

pub struct CudaDetect {
    pub status: CudaStatus,
    pub device_name: String,
    pub compute_capability: (u32, u32),
}

impl CudaDetect {
    pub fn init() -> Self {
        if let Some(ctx) = try_detect_gpu() {
            ctx
        } else {
            CudaDetect {
                status: CudaStatus::Unavailable,
                device_name: String::new(),
                compute_capability: (0, 0),
            }
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self.status, CudaStatus::Available { .. })
    }
}

fn try_detect_gpu() -> Option<CudaDetect> {
    let output = std::process::Command::new("nvidia-smi")
        .arg("--query-gpu=name,compute_cap")
        .arg("--format=csv,noheader,nounits")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let info = String::from_utf8_lossy(&output.stdout);
    let line = info.lines().next()?;
    let parts: Vec<&str> = line.splitn(2, ',').collect();
    let name = parts.get(0)?.trim().to_string();
    let cap_str = parts.get(1).unwrap_or(&"0.0").trim();
    let cap_parts: Vec<u32> = cap_str.split('.').filter_map(|s| s.parse().ok()).collect();
    let major = cap_parts.get(0).copied().unwrap_or(0);
    let minor = cap_parts.get(1).copied().unwrap_or(0);

    Some(CudaDetect {
        status: CudaStatus::Available { device_count: 1 },
        device_name: name,
        compute_capability: (major, minor),
    })
}

pub fn kernel_ready() -> bool {
    Path::new("cuda/scanner.ptx").exists()
}

pub fn print_cuda_info(ctx: &CudaDetect) {
    match ctx.status {
        CudaStatus::Available { device_count } => {
            println!("  [CUDA] {} device(s) detected", device_count);
            println!("  [CUDA] GPU: {}", ctx.device_name);
            println!(
                "  [CUDA] Compute Capability: {}.{}",
                ctx.compute_capability.0, ctx.compute_capability.1
            );
            if kernel_ready() {
                println!("  [CUDA] Kernel: scanner.ptx ready (full pipeline)");
            } else {
                println!("  [CUDA] Kernel: not found, using CPU fallback");
                println!("  [CUDA] Build: nvcc -O3 -arch=sm_75 --ptx cuda/scanner.cu -o cuda/scanner.ptx");
            }
        }
        CudaStatus::Unavailable => {
            println!("  [CUDA] No NVIDIA GPU detected, using Rayon (CPU)");
        }
    }
}

/// GPU BinaryFuse8 filter data that gets uploaded to device
pub struct GpuFilterData {
    pub segment_length: u32,
    pub segment_count_length: u32,
    pub segment_length_mask: u32,
    pub array_length: u32,
    pub seed: u64,
    pub fingerprints: Vec<u8>,
}

/// Double-buffered GPU accelerator with full pipeline support
pub struct GpuAccelerator {
    #[allow(dead_code)]
    ctx: Arc<CudaContext>,
    stream_a: Arc<CudaStream>,
    stream_b: Arc<CudaStream>,
    func_full: Option<CudaFunction>,
    func_pbkdf2: CudaFunction,
    max_batch: u32,
    filter_device: Option<DeviceFilter>,
}

pub struct PendingPbkdf2 {
    d_seeds: CudaSlice<u8>,
    count: usize,
    stream: Arc<CudaStream>,
}

pub struct PendingH160 {
    d_h160: CudaSlice<u8>,
    count: usize,
    num_paths: usize,
    depth: u32,
    stream: Arc<CudaStream>,
}

impl PendingH160 {
    pub fn collect(self) -> Result<Vec<u8>, String> {
        if self.count == 0 {
            return Ok(vec![]);
        }
        self.stream.synchronize().map_err(|e| format!("sync: {:?}", e))?;
        let data = self.stream.clone_dtoh(&self.d_h160)
            .map_err(|e| format!("dtoh h160: {:?}", e))?;
        Ok(data)
    }

    pub fn count(&self) -> usize { self.count }
    pub fn num_paths(&self) -> usize { self.num_paths }
    pub fn depth(&self) -> u32 { self.depth }
}

impl PendingPbkdf2 {
    pub fn collect(self) -> Result<Vec<[u8; 64]>, String> {
        self.stream.synchronize().map_err(|e| format!("sync: {:?}", e))?;
        let host_seeds = self.stream.clone_dtoh(&self.d_seeds)
            .map_err(|e| format!("dtoh: {:?}", e))?;
        let seeds: Vec<[u8; 64]> = host_seeds
            .chunks_exact(64)
            .take(self.count)
            .map(|c| {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(c);
                arr
            })
            .collect();
        Ok(seeds)
    }
}

struct DeviceFilter {
    segment_length: u32,
    segment_count_length: u32,
    segment_length_mask: u32,
    array_length: u32,
    seed: u64,
    fingerprints: CudaSlice<u8>,
}

impl GpuAccelerator {
    pub fn new(filter_data: Option<&GpuFilterData>) -> Result<Self, String> {
        let ptx_path = Path::new("cuda/scanner.ptx");
        if !ptx_path.exists() {
            return Err("cuda/scanner.ptx not found".into());
        }

        let ctx = CudaContext::new(0)
            .map_err(|e| format!("CUDA context: {:?}", e))?;

        let module = ctx.load_module(Ptx::from_file(ptx_path))
            .map_err(|e| format!("Load module: {:?}", e))?;

        let func_pbkdf2 = module.load_function("pbkdf2_batch")
            .map_err(|e| format!("Load pbkdf2_batch: {:?}", e))?;

        let func_full = module.load_function("scan_full_pipeline").ok();

        // P1: Create two streams for double-buffering
        let stream_a = ctx.default_stream();
        let stream_b = stream_a.fork()
            .map_err(|e| format!("Create stream B: {:?}", e))?;

        // Upload BinaryFuse8 filter to GPU
        let filter_device = if let Some(fd) = filter_data {
            let d_fp = stream_a.clone_htod(&fd.fingerprints)
                .map_err(|e| format!("Upload filter: {:?}", e))?;
            Some(DeviceFilter {
                segment_length: fd.segment_length,
                segment_count_length: fd.segment_count_length,
                segment_length_mask: fd.segment_length_mask,
                array_length: fd.array_length,
                seed: fd.seed,
                fingerprints: d_fp,
            })
        } else {
            None
        };

        let mode = if func_full.is_some() && filter_device.is_some() {
            "Full Pipeline (PBKDF2+secp256k1+filter on GPU)"
        } else {
            "PBKDF2-only on GPU"
        };
        println!("  [CUDA] Mode: {}", mode);
        println!("  [CUDA] Double-buffer streams: enabled");

        Ok(GpuAccelerator {
            ctx,
            stream_a,
            stream_b,
            func_full,
            func_pbkdf2,
            max_batch: 32768,
            filter_device,
        })
    }

    /// Full pipeline scan: returns indices of mnemonics that matched the filter
    pub fn scan_full_batch(
        &self,
        mnemonics: &[String],
        depth: u32,
        use_stream_b: bool,
    ) -> Result<Vec<u32>, String> {
        let func = self.func_full.as_ref()
            .ok_or("scan_full_pipeline kernel not loaded")?;
        let filter = self.filter_device.as_ref()
            .ok_or("Filter not uploaded to GPU")?;

        let stream = if use_stream_b { &self.stream_b } else { &self.stream_a };
        let count = mnemonics.len();
        if count == 0 {
            return Ok(vec![]);
        }

        let max_len = mnemonics.iter().map(|m| m.len()).max().unwrap_or(0);
        let stride = ((max_len + 3) / 4) * 4;

        let mut packed = vec![0u8; count * stride];
        let mut lens = vec![0u32; count];
        for (i, m) in mnemonics.iter().enumerate() {
            let b = m.as_bytes();
            lens[i] = b.len() as u32;
            packed[i * stride..i * stride + b.len()].copy_from_slice(b);
        }

        let count_u32 = count as u32;
        let stride_u32 = stride as u32;
        let num_paths: u32 = 3;
        let hit_h160_size = count * (num_paths as usize) * (depth as usize) * 20;

        let d_mnemonics = stream.clone_htod(&packed)
            .map_err(|e| format!("htod mnemonics: {:?}", e))?;
        let d_lens = stream.clone_htod(&lens)
            .map_err(|e| format!("htod lens: {:?}", e))?;
        let mut d_hits = stream.alloc_zeros::<u32>(count)
            .map_err(|e| format!("alloc hits: {:?}", e))?;
        let mut d_hit_h160 = stream.alloc_zeros::<u8>(hit_h160_size)
            .map_err(|e| format!("alloc h160: {:?}", e))?;

        let block_size = 256u32;
        let grid_size = (count_u32 + block_size - 1) / block_size;
        let cfg = LaunchConfig {
            grid_dim: (grid_size, 1, 1),
            block_dim: (block_size, 1, 1),
            shared_mem_bytes: 0,
        };

        unsafe {
            stream.launch_builder(func)
                .arg(&d_mnemonics)
                .arg(&d_lens)
                .arg(&count_u32)
                .arg(&stride_u32)
                .arg(&depth)
                .arg(&filter.segment_length)
                .arg(&filter.segment_count_length)
                .arg(&filter.segment_length_mask)
                .arg(&filter.array_length)
                .arg(&filter.seed)
                .arg(&filter.fingerprints)
                .arg(&mut d_hits)
                .arg(&mut d_hit_h160)
                .launch(cfg)
                .map_err(|e| format!("launch full pipeline: {:?}", e))?;
        }

        stream.synchronize().map_err(|e| format!("sync: {:?}", e))?;

        let host_hits = stream.clone_dtoh(&d_hits)
            .map_err(|e| format!("dtoh hits: {:?}", e))?;

        let hit_indices: Vec<u32> = host_hits.iter().enumerate()
            .filter(|(_, &v)| v != 0)
            .map(|(i, _)| i as u32)
            .collect();

        Ok(hit_indices)
    }

    /// GPU-heavy pipeline: PBKDF2 + secp256k1 + BIP32 + hash160 all on GPU
    /// Returns raw hash160 bytes for ALL derived addresses (count * num_paths * depth * 20 bytes)
    /// CPU only needs to encode addresses and match against filter
    pub fn derive_h160_batch(
        &self,
        mnemonics: &[String],
        depth: u32,
        use_stream_b: bool,
    ) -> Result<Vec<u8>, String> {
        let func = self.func_full.as_ref()
            .ok_or("full pipeline kernel not loaded")?;
        let filter = self.filter_device.as_ref()
            .ok_or("Filter not uploaded to GPU")?;

        let stream = if use_stream_b { &self.stream_b } else { &self.stream_a };
        let count = mnemonics.len();
        if count == 0 {
            return Ok(vec![]);
        }

        let max_len = mnemonics.iter().map(|m| m.len()).max().unwrap_or(0);
        let stride = ((max_len + 3) / 4) * 4;

        let mut packed = vec![0u8; count * stride];
        let mut lens = vec![0u32; count];
        for (i, m) in mnemonics.iter().enumerate() {
            let b = m.as_bytes();
            lens[i] = b.len() as u32;
            packed[i * stride..i * stride + b.len()].copy_from_slice(b);
        }

        let count_u32 = count as u32;
        let stride_u32 = stride as u32;
        let num_paths: u32 = 3;
        let h160_total = count * (num_paths as usize) * (depth as usize) * 20;

        let d_mnemonics = stream.clone_htod(&packed)
            .map_err(|e| format!("htod mnemonics: {:?}", e))?;
        let d_lens = stream.clone_htod(&lens)
            .map_err(|e| format!("htod lens: {:?}", e))?;
        let mut d_hits = stream.alloc_zeros::<u32>(count)
            .map_err(|e| format!("alloc hits: {:?}", e))?;
        let mut d_hit_h160 = stream.alloc_zeros::<u8>(h160_total)
            .map_err(|e| format!("alloc h160: {:?}", e))?;

        let block_size = 256u32;
        let grid_size = (count_u32 + block_size - 1) / block_size;
        let cfg = LaunchConfig {
            grid_dim: (grid_size, 1, 1),
            block_dim: (block_size, 1, 1),
            shared_mem_bytes: 0,
        };

        unsafe {
            stream.launch_builder(func)
                .arg(&d_mnemonics)
                .arg(&d_lens)
                .arg(&count_u32)
                .arg(&stride_u32)
                .arg(&depth)
                .arg(&filter.segment_length)
                .arg(&filter.segment_count_length)
                .arg(&filter.segment_length_mask)
                .arg(&filter.array_length)
                .arg(&filter.seed)
                .arg(&filter.fingerprints)
                .arg(&mut d_hits)
                .arg(&mut d_hit_h160)
                .launch(cfg)
                .map_err(|e| format!("launch derive_h160: {:?}", e))?;
        }

        stream.synchronize().map_err(|e| format!("sync: {:?}", e))?;

        let h160_data = stream.clone_dtoh(&d_hit_h160)
            .map_err(|e| format!("dtoh h160: {:?}", e))?;

        Ok(h160_data)
    }

    /// Non-blocking version of derive_h160_batch
    pub fn derive_h160_launch(
        &self,
        mnemonics: &[String],
        depth: u32,
        use_stream_b: bool,
    ) -> Result<PendingH160, String> {
        let func = self.func_full.as_ref()
            .ok_or("full pipeline kernel not loaded")?;
        let filter = self.filter_device.as_ref()
            .ok_or("Filter not uploaded to GPU")?;

        let stream = if use_stream_b { &self.stream_b } else { &self.stream_a };
        let count = mnemonics.len();
        if count == 0 {
            let d = stream.alloc_zeros::<u8>(1)
                .map_err(|e| format!("alloc: {:?}", e))?;
            return Ok(PendingH160 { d_h160: d, count: 0, num_paths: 3, depth, stream: stream.clone() });
        }

        let max_len = mnemonics.iter().map(|m| m.len()).max().unwrap_or(0);
        let stride = ((max_len + 3) / 4) * 4;

        let mut packed = vec![0u8; count * stride];
        let mut lens = vec![0u32; count];
        for (i, m) in mnemonics.iter().enumerate() {
            let b = m.as_bytes();
            lens[i] = b.len() as u32;
            packed[i * stride..i * stride + b.len()].copy_from_slice(b);
        }

        let count_u32 = count as u32;
        let stride_u32 = stride as u32;
        let num_paths: u32 = 3;
        let h160_total = count * (num_paths as usize) * (depth as usize) * 20;

        let d_mnemonics = stream.clone_htod(&packed)
            .map_err(|e| format!("htod mnemonics: {:?}", e))?;
        let d_lens = stream.clone_htod(&lens)
            .map_err(|e| format!("htod lens: {:?}", e))?;
        let mut d_hits = stream.alloc_zeros::<u32>(count)
            .map_err(|e| format!("alloc hits: {:?}", e))?;
        let mut d_h160 = stream.alloc_zeros::<u8>(h160_total)
            .map_err(|e| format!("alloc h160: {:?}", e))?;

        let block_size = 256u32;
        let grid_size = (count_u32 + block_size - 1) / block_size;
        let cfg = LaunchConfig {
            grid_dim: (grid_size, 1, 1),
            block_dim: (block_size, 1, 1),
            shared_mem_bytes: 0,
        };

        unsafe {
            stream.launch_builder(func)
                .arg(&d_mnemonics)
                .arg(&d_lens)
                .arg(&count_u32)
                .arg(&stride_u32)
                .arg(&depth)
                .arg(&filter.segment_length)
                .arg(&filter.segment_count_length)
                .arg(&filter.segment_length_mask)
                .arg(&filter.array_length)
                .arg(&filter.seed)
                .arg(&filter.fingerprints)
                .arg(&mut d_hits)
                .arg(&mut d_h160)
                .launch(cfg)
                .map_err(|e| format!("launch derive_h160: {:?}", e))?;
        }

        Ok(PendingH160 { d_h160, count, num_paths: num_paths as usize, depth, stream: stream.clone() })
    }

    /// Legacy: PBKDF2-only batch (returns seeds for CPU-side derivation)
    pub fn pbkdf2_batch(
        &self,
        mnemonics: &[String],
        use_stream_b: bool,
    ) -> Result<Vec<[u8; 64]>, String> {
        let stream = if use_stream_b { &self.stream_b } else { &self.stream_a };
        let count = mnemonics.len();
        if count == 0 {
            return Ok(vec![]);
        }

        let max_len = mnemonics.iter().map(|m| m.len()).max().unwrap_or(0);
        let stride = ((max_len + 3) / 4) * 4;

        let mut packed = vec![0u8; count * stride];
        let mut lens = vec![0u32; count];
        for (i, m) in mnemonics.iter().enumerate() {
            let b = m.as_bytes();
            lens[i] = b.len() as u32;
            packed[i * stride..i * stride + b.len()].copy_from_slice(b);
        }

        let count_u32 = count as u32;
        let stride_u32 = stride as u32;

        let d_mnemonics = stream.clone_htod(&packed)
            .map_err(|e| format!("htod mnemonics: {:?}", e))?;
        let d_lens = stream.clone_htod(&lens)
            .map_err(|e| format!("htod lens: {:?}", e))?;
        let mut d_seeds = stream.alloc_zeros::<u8>(count * 64)
            .map_err(|e| format!("alloc seeds: {:?}", e))?;

        let block_size = 256u32;
        let grid_size = (count_u32 + block_size - 1) / block_size;
        let cfg = LaunchConfig {
            grid_dim: (grid_size, 1, 1),
            block_dim: (block_size, 1, 1),
            shared_mem_bytes: 0,
        };

        unsafe {
            stream.launch_builder(&self.func_pbkdf2)
                .arg(&d_mnemonics)
                .arg(&d_lens)
                .arg(&count_u32)
                .arg(&stride_u32)
                .arg(&mut d_seeds)
                .launch(cfg)
                .map_err(|e| format!("launch pbkdf2: {:?}", e))?;
        }

        stream.synchronize().map_err(|e| format!("sync: {:?}", e))?;

        let host_seeds = stream.clone_dtoh(&d_seeds)
            .map_err(|e| format!("dtoh: {:?}", e))?;

        let seeds: Vec<[u8; 64]> = host_seeds
            .chunks_exact(64)
            .map(|c| {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(c);
                arr
            })
            .collect();

        Ok(seeds)
    }

    /// Non-blocking PBKDF2 launch — returns a handle to collect later
    pub fn pbkdf2_launch(
        &self,
        mnemonics: &[String],
        use_stream_b: bool,
    ) -> Result<PendingPbkdf2, String> {
        let stream = if use_stream_b { &self.stream_b } else { &self.stream_a };
        let count = mnemonics.len();
        if count == 0 {
            let d_seeds = stream.alloc_zeros::<u8>(64)
                .map_err(|e| format!("alloc: {:?}", e))?;
            return Ok(PendingPbkdf2 { d_seeds, count: 0, stream: stream.clone() });
        }

        let max_len = mnemonics.iter().map(|m| m.len()).max().unwrap_or(0);
        let stride = ((max_len + 3) / 4) * 4;

        let mut packed = vec![0u8; count * stride];
        let mut lens = vec![0u32; count];
        for (i, m) in mnemonics.iter().enumerate() {
            let b = m.as_bytes();
            lens[i] = b.len() as u32;
            packed[i * stride..i * stride + b.len()].copy_from_slice(b);
        }

        let count_u32 = count as u32;
        let stride_u32 = stride as u32;

        let d_mnemonics = stream.clone_htod(&packed)
            .map_err(|e| format!("htod mnemonics: {:?}", e))?;
        let d_lens = stream.clone_htod(&lens)
            .map_err(|e| format!("htod lens: {:?}", e))?;
        let mut d_seeds = stream.alloc_zeros::<u8>(count * 64)
            .map_err(|e| format!("alloc seeds: {:?}", e))?;

        let block_size = 256u32;
        let grid_size = (count_u32 + block_size - 1) / block_size;
        let cfg = LaunchConfig {
            grid_dim: (grid_size, 1, 1),
            block_dim: (block_size, 1, 1),
            shared_mem_bytes: 0,
        };

        unsafe {
            stream.launch_builder(&self.func_pbkdf2)
                .arg(&d_mnemonics)
                .arg(&d_lens)
                .arg(&count_u32)
                .arg(&stride_u32)
                .arg(&mut d_seeds)
                .launch(cfg)
                .map_err(|e| format!("launch pbkdf2: {:?}", e))?;
        }

        Ok(PendingPbkdf2 { d_seeds, count, stream: stream.clone() })
    }

    pub fn has_full_pipeline(&self) -> bool {
        self.func_full.is_some() && self.filter_device.is_some()
    }

    pub fn max_batch_size(&self) -> u32 {
        self.max_batch
    }

    pub fn mode_label(&self) -> &'static str {
        if self.has_full_pipeline() {
            "CUDA Full (PBKDF2+secp256k1+hash160 on GPU)"
        } else {
            "CUDA (PBKDF2) + CPU derive"
        }
    }
}
