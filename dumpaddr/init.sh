#!/bin/bash
# init.sh - Deploy Bitcoin Core node on Ubuntu 24 via snap (fast initial sync)
# Usage: chmod +x init.sh && sudo ./init.sh
set -e

DATADIR="/data/bitcoin"
SNAP_URL="https://prunednode.today/latest.tar.gz"

echo "============================================"
echo "  Bitcoin Core Node Setup (Ubuntu 24)"
echo "  Method: snap install + snapshot sync"
echo "============================================"
echo

# 1. Install Bitcoin Core via snap
echo "[1/6] Installing Bitcoin Core via snap..."
if ! command -v bitcoin-cli &>/dev/null; then
    snap install bitcoin-core
    # Create symlinks for convenience
    ln -sf /snap/bitcoin-core/current/bin/bitcoind /usr/local/bin/bitcoind
    ln -sf /snap/bitcoin-core/current/bin/bitcoin-cli /usr/local/bin/bitcoin-cli
    echo "  Installed: $(bitcoind --version | head -1)"
else
    echo "  Already installed: $(bitcoin-cli --version | head -1)"
fi

# 2. Create data directory
echo "[2/6] Creating data directory: $DATADIR"
mkdir -p "$DATADIR"

# 3. Write bitcoin.conf
echo "[3/6] Writing bitcoin.conf..."
cat > "$DATADIR/bitcoin.conf" <<'EOF'
server=1
daemon=1
txindex=0
prune=0
dbcache=4096
maxconnections=40
rpcuser=btcnode
rpcpassword=btcnode_local_only
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
datadir=/data/bitcoin
EOF
echo "  Config written to $DATADIR/bitcoin.conf"

# 4. Download blockchain snapshot (optional, for fast sync)
echo "[4/6] Downloading blockchain snapshot for fast sync..."
echo "  This downloads a pruned/full snapshot to skip weeks of syncing."
echo "  Source: $SNAP_URL"
echo
read -p "  Download snapshot? (y/n, default: y): " DOWNLOAD_SNAP
DOWNLOAD_SNAP=${DOWNLOAD_SNAP:-y}

if [[ "$DOWNLOAD_SNAP" == "y" || "$DOWNLOAD_SNAP" == "Y" ]]; then
    if [ -d "$DATADIR/blocks" ] && [ "$(ls -A $DATADIR/blocks 2>/dev/null)" ]; then
        echo "  [SKIP] blocks/ directory already exists, skipping download"
    else
        echo "  Downloading... (this may take 30-60 minutes depending on bandwidth)"
        apt-get install -y aria2 2>/dev/null || true
        if command -v aria2c &>/dev/null; then
            aria2c -x 16 -s 16 -d /tmp -o btc_snapshot.tar.gz "$SNAP_URL"
        else
            wget -O /tmp/btc_snapshot.tar.gz "$SNAP_URL"
        fi
        echo "  Extracting snapshot..."
        tar -xzf /tmp/btc_snapshot.tar.gz -C "$DATADIR"
        rm -f /tmp/btc_snapshot.tar.gz
        echo "  Snapshot extracted to $DATADIR"
    fi
else
    echo "  [SKIP] Will sync from scratch (may take days)"
fi

# 5. Start bitcoind
echo "[5/6] Starting bitcoind..."
if pgrep -x bitcoind >/dev/null; then
    echo "  bitcoind is already running"
else
    bitcoind -datadir="$DATADIR" -daemon
    sleep 3
    if pgrep -x bitcoind >/dev/null; then
        echo "  bitcoind started successfully"
    else
        echo "  [ERROR] Failed to start bitcoind, check logs at $DATADIR/debug.log"
        exit 1
    fi
fi

# 6. Check sync status
echo "[6/6] Checking sync status..."
sleep 2
BLOCKS=$(bitcoin-cli -datadir="$DATADIR" getblockcount 2>/dev/null || echo "N/A")
HEADERS=$(bitcoin-cli -datadir="$DATADIR" getblockchaininfo 2>/dev/null | grep -o '"headers": [0-9]*' | grep -o '[0-9]*' || echo "N/A")
echo "  Current height: $BLOCKS / $HEADERS"

echo
echo "============================================"
echo "  Setup Complete!"
echo "============================================"
echo
echo "  Data directory:  $DATADIR"
echo "  Config file:     $DATADIR/bitcoin.conf"
echo "  RPC:             127.0.0.1:8332"
echo
echo "  Commands:"
echo "    bitcoin-cli -datadir=$DATADIR getblockcount"
echo "    bitcoin-cli -datadir=$DATADIR getblockchaininfo"
echo
echo "  After full sync, run:"
echo "    python3 main.py"
echo "  to export UTXO addresses."
echo
