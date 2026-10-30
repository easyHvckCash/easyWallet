#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="$ROOT/dist"
CUDA_SRC="$ROOT/cuda"

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Darwin) PLATFORM="macos" ;;
    Linux)  PLATFORM="linux" ;;
    *)      echo "[ERROR] Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH_CPU="$(uname -m)"

echo "============================================"
echo "  BTC Scanner - Build Script ($PLATFORM $ARCH_CPU)"
echo "  CUDA kernel + Rust release + package"
echo "============================================"
echo ""

# ========== Step 1: CUDA Kernel (optional on macOS) ==========
CUDA_AVAILABLE=0

if command -v nvcc &>/dev/null; then
    echo "[1/3] Compiling CUDA kernel..."
    echo "      Source: cuda/scanner.cu"

    # Auto-detect GPU architecture
    if command -v nvidia-smi &>/dev/null; then
        GPU_ARCH=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -1 | tr -d '.' | sed 's/^/sm_/')
        if [ -z "$GPU_ARCH" ]; then
            GPU_ARCH="sm_75"
        fi
    else
        GPU_ARCH="sm_75"
    fi
    echo "      Arch:   $GPU_ARCH"

    pushd "$CUDA_SRC" >/dev/null
    if nvcc -O3 -arch="$GPU_ARCH" --ptx scanner.cu -o scanner.ptx \
        --use_fast_math \
        -Xptxas -v \
        -DNDEBUG 2>&1; then
        echo "[OK] scanner.ptx generated"
        CUDA_AVAILABLE=1
    else
        echo "[WARN] CUDA kernel compilation failed, continuing without GPU support"
    fi
    popd >/dev/null
else
    echo "[1/3] CUDA not available (nvcc not found)"
    if [ "$PLATFORM" = "macos" ]; then
        echo "      macOS: CUDA not supported by Apple, will build CPU-only"
    else
        echo "      Install CUDA Toolkit: https://developer.nvidia.com/cuda-downloads"
    fi
fi
echo ""

# ========== Step 2: Vue Frontend Build ==========
echo "[2/4] Building Vue frontend..."

if ! command -v npm &>/dev/null; then
    echo "[WARN] npm not found, skipping frontend build"
    echo "       Install Node.js: https://nodejs.org"
else
    pushd "$ROOT/webui" >/dev/null
    npm install --silent 2>&1
    npm run build 2>&1
    echo "[OK] Vue frontend build succeeded"
    popd >/dev/null
fi
echo ""

# ========== Step 3: Rust Release Build ==========
echo "[3/4] Building Rust project (release)..."

if ! command -v cargo &>/dev/null; then
    echo "[ERROR] cargo not found in PATH"
    echo "        Install Rust: https://rustup.rs"
    exit 1
fi

pushd "$ROOT" >/dev/null
cargo build --release 2>&1
echo "[OK] Rust build succeeded"
popd >/dev/null
echo ""

# ========== Step 4: Package to dist/ ==========
echo "[4/4] Packaging to dist/ ..."

# Determine binary name
BIN_NAME="btc-cuda-scanner"
BIN_SRC="$ROOT/target/release/$BIN_NAME"

if [ ! -f "$BIN_SRC" ]; then
    echo "[ERROR] Binary not found at $BIN_SRC"
    exit 1
fi

# Clean old binary and PTX only (preserve files/)
rm -f "$DIST/$BIN_NAME"
rm -f "$DIST/cuda/scanner.ptx"

# Create directory structure
mkdir -p "$DIST"
mkdir -p "$DIST/cuda"
mkdir -p "$DIST/files"
mkdir -p "$DIST/files/waittocheck"

# Copy binary
cp "$BIN_SRC" "$DIST/"
chmod +x "$DIST/$BIN_NAME"
echo "      Copied: $BIN_NAME"

# Copy PTX if available
if [ "$CUDA_AVAILABLE" -eq 1 ] && [ -f "$CUDA_SRC/scanner.ptx" ]; then
    cp "$CUDA_SRC/scanner.ptx" "$DIST/cuda/"
    echo "      Copied: cuda/scanner.ptx"
fi

# Copy Vue frontend
if [ -d "$ROOT/webui/dist" ]; then
    rm -rf "$DIST/webui"
    cp -r "$ROOT/webui/dist" "$DIST/webui"
    echo "      Copied: webui/ (Vue SPA)"
fi

# Copy pending task files
if ls "$ROOT/files/waittocheck/"*.txt &>/dev/null 2>&1; then
    cp "$ROOT/files/waittocheck/"*.txt "$DIST/files/waittocheck/"
    echo "      Copied: waittocheck/*.txt"
fi

echo ""
echo "============================================"
echo "  Build Complete! ($PLATFORM $ARCH_CPU)"
echo "============================================"
echo ""
echo "  Output:  $DIST/"
echo "  Binary:  dist/$BIN_NAME"
if [ "$CUDA_AVAILABLE" -eq 1 ]; then
echo "  Kernel:  dist/cuda/scanner.ptx"
else
echo "  Kernel:  (none - CPU mode)"
fi
echo ""
echo "  Runtime layout:"
echo "    dist/$BIN_NAME"
echo "    dist/cuda/scanner.ptx"
echo "    dist/files/waittocheck/         (task files)"
echo "    ../humanaction/addr/             (utxo_addresses.set)"
echo "    ../humanaction/pocs/             (POC generators)"
echo ""
echo "  Usage (master):"
echo "    ./$BIN_NAME --role master --listenon 8877 --token SECRET"
echo ""
echo "  Usage (node):"
echo "    ./$BIN_NAME --role node --server IP:8877 --token SECRET"
echo ""
echo "  Dashboard: http://localhost:8877/"
echo "============================================"
