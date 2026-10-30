# easyWallet

> ⚠️ **Security Incident Disclosure**: During AI-assisted development, I explicitly requested the AI to redact a test mnemonic, but it still embedded the full mnemonic into frontend i18n placeholder text. Although it was a test-only mnemonic, this exposes an uncontrollable risk in AI-assisted development — prompt-level constraints are not reliable for sensitive data handling. [Full incident post-mortem](https://easyhvckcash.auths.cloud/notes/first-time-hacked)

The #1 open-source private key cracking framework. Comprehensive integration of public POCs, GPU-accelerated, leading weak-entropy wallet exploit solution.

Website: https://easyhackcash.auths.cloud/easywallet (live data from a real running cluster — currently a single home desktop)

[中文文档](README_CN.md)

---

## Public POCs

| POC ID | Name | Severity | Effective Entropy | Speed | Coverage | Reference |
|--------|------|----------|-------------------|-------|----------|-----------|
| `dice_no_floor` | Coldcard dice path no entropy floor | defense-in-depth failure | 2.585N bit | ~50,000/s | 2017 ~ present | [Coldcard source](https://github.com/Coldcard/firmware) |
| `yasmarang_bypass` | Coldcard TRNG erroneously linked to Yasmarang | critical (~594 BTC stolen) | 32 bit | ~40,000/s | 2019 ~ 2020 | [Disclosure](https://github.com/nwfella/coldcard-entropy-incident) |
| `tw_wasm_mt19937` | TrustWallet WASM MT19937 weak seed | critical (32 bit) | 32 bit | ~8,000/s | 2022-11 ~ 2023-04 | [CVE-2023-31290](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31290) |
| `tw_ios_minstd` | TrustWallet iOS minstd_rand0 LCG | critical (31 bit, exploited 2023-07) | 31 bit | ~40,000/s | 2018-03 ~ 2018-12 | [CVE-2024-23660](https://milksad.info/posts/research-update-5/) |
| `ill_bloom` | Blockchain.info CryptoJS MWC PRNG | critical (39-40 bit, $5M+ stolen) | ~39 bit | ~8,000/s | 2012 ~ 2023 | [CVE-2026-71851](https://blog.coinspect.com/) |
| `mt19937_time_seed` | Python random.seed(time) generic pattern | critical (27.7 bit) | 27.7 bit | ~50,000/s | 2009 ~ 2015 | Generic misuse |
| `milksad_bx_seed` | Libbitcoin bx seed MT19937 | critical (32 bit, $900K+, 227K wallets) | 32 bit | ~30,000/s | 2017 ~ 2023 | [Milk Sad CVE-2023-39910](https://milksad.info/disclosure.html) |
| `chosen_one` | Chosen One (full 2^256 random sampling) | none (unbreakable) | 256 bit | ~50,000/s | all time | BIP-39 standard random |

Additional private POCs not listed.

## Why This Work Matters

A Bitcoin private key is a 256-bit random number with 2²⁵⁶ (≈1.16×10⁷⁷) possible values — a number so vast it exceeds the total atoms in the observable universe. If keys were truly random, brute-force is physically impossible.

But in reality, nobody manually picks 256 random bits. Everyone relies on wallet software to generate their private keys. The problem is: **some wallet products used naive implementations for key generation**, collapsing the theoretical 2²⁵⁶ space down to 2³² or even smaller.

By enumerating these tiny spaces, an attacker can reconstruct every affected wallet's private key and steal user funds. This is not theoretical — the public incidents corresponding to the POCs listed above have proven the attacks work.

You have to respect the early movers — they had both the insight to identify these flaws and the execution to act on them. But it's not too late. The goal of this project is: **let a home PC join this game**. With GPU acceleration and distributed computing, a single RTX 4060 Ti can sweep a 2³² key space in under 24 hours.

---

## Project Performance

| Hardware | Speed | 2³² Full-Space Coverage |
|----------|-------|------------------------|
| RTX 2060 Super ×1 | ~20K/s | ~58.2h |
| RTX 4060 Ti ×1 | ~50K/s | ~23.9h |
| B300 ×1 | ~175K/s | ~6.8h |
| B300 ×8 | ~1.4M/s | ~51min |
| B300 ×64 | ~11.2M/s | ~6.4min |

**POC Severity Rating**: Based on effective entropy (BIP-39 requires at least 128-bit cryptographically secure random entropy)

| Level | Entropy | Risk |
|-------|---------|------|
| Low | ≤ 80 bit | Theoretically weak |
| Medium | ≤ 50 bit | Feasible with dedicated hardware |
| High | ≤ 40 bit | Practical attack within days |
| Critical | ≤ 30 bit | Exploitable within hours |

**6-month attack surface**:

| Hardware | Unsafe space |
|----------|-------------|
| B300 ×1 | ≤ 2⁴¹ |
| B300 ×8 | ≤ 2⁴⁴ |
| B300 ×64 | ≤ 2⁴⁷ |

---

## Quick Start

### 2.1 Obtain UTXO Address Set

**Option A: Deploy a Bitcoin node and export**

1. Deploy an Ubuntu 24 VM
2. Run `dumpaddr/init.sh` to install Bitcoin Core and sync the blockchain
3. After sync, run `python3 dumpaddr/main.py` to export UTXO addresses

**Option B: Direct download (recommended)**

Download: https://mega.nz/file/T8BXBTyK#Vx2L3Qg1ue1ET5mgt5qvnNct2vgg_xy-tRUwTJh2p8o

You will get `utxo_addresses.set` (~2.17GB). Place it in `humanaction/addr/`.

---

### 2.2 Environment Setup

#### 2.2.1 Windows 11

Install NVIDIA drivers:
https://www.nvidia.com/en-us/drivers/ — search for your GPU model

Install VS Build Tools (install first, then install CUDA):
Download: https://aka.ms/vs/17/release/vs_BuildTools.exe
```
.\vs_BuildTools.exe --wait --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended
```

Install CUDA Toolkit 12.x:
Download: https://developer.nvidia.com/cuda-downloads (select full installation, not express)

Install Rust toolchain:
https://rustup.rs/

Restart the machine.

Build:
```bash
build.bat
cd dist
```

Open two CMD windows:

Master:
```bash
./btc-cuda-scanner.exe --role master --listenon 8877 --token mysecret --user admin --passwd admin
```

Node:
```bash
./btc-cuda-scanner.exe --role node --server 127.0.0.1:8877 --token mysecret
```

**Quick single-machine test (recommended):**

```bash
run.bat
```

`run.bat` is a one-click script that automatically kills any running instances, rebuilds everything (CUDA PTX + Vue frontend + Rust), then launches a Master node and a Worker node on the same machine. Ideal for local testing — just run it and open http://localhost:8877/.

Open browser at http://localhost:8877/ to access the dashboard.

#### 2.2.2 Linux

Rust supports Linux compilation, but untested. Contributions welcome.

```bash
chmod +x build.sh
./build.sh
cd dist
./btc-cuda-scanner --role master --listenon 8877 --token mysecret --user admin --passwd admin
```

---

### 2.3 Dashboard Usage

1. **POC Test page**: Click the Start button for a POC — the Master generates mnemonic/privkey task files based on the POC code
2. **Scanner page**: Click "Start Dispatch" (master gate) — only after this is enabled can Nodes pull tasks. Switch each Node between GPU/CPU mode, or selectively pause/start specific nodes. Newly connected Nodes start paused — enable them manually
3. **Hit Records page**: View all discovered weak-entropy addresses, including source mnemonic/privkey, associated POC, discovery time, etc.
4. **Benchmark page**: If you doubt scanning accuracy, input a known mnemonic or private key with assets, select a paused Node, and run a benchmark to verify hit detection correctness

---

### 2.4 Add/Modify POCs

Edit files under `humanaction/pocs/`:
- `pocinfo.json` — POC metadata
- `targets/<vendor>/<poc_id>/generator.py` — generator script

To add a new POC, create the generator.py and register it in pocinfo.json.

After making changes, click the **Reload** button on the POC Test page to apply. If a POC errors out, click its **Details** button to view the error log.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│   Master (--role master --listenon 8877)        │
│                                                 │
│   - POC task generation (Python)                │
│   - Task queue distribution                     │
│   - Cluster Dashboard (unified panel)           │
│   - Node status management + task timeout retry │
│                                                 │
│   Dashboard: http://master_ip:8877/             │
└──────────────────────┬──────────────────────────┘
                       │ HTTP Pull (Node actively pulls)
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  Node A     │ │  Node B     │ │  Node N     │
│  RTX 2060S  │ │  RTX 4060Ti │ │  RTX 4090   │
│             │ │             │ │             │
│  - GPU scan │ │  - GPU scan │ │  - GPU scan │
│  - Local DB │ │  - Local DB │ │  - Local DB │
│  - Retry    │ │  - Retry    │ │  - Retry    │
└─────────────┘ └─────────────┘ └─────────────┘
```

---

## Credits

Entirely developed by Claude Opus 4.6. Not handcrafted.

## License

MIT License — see [LICENSE](bitcoin/win11/LICENSE)
