# easyWallet

开源弱熵钱包漏洞复现研究框架。集成已公开 CVE 的 Proof-of-Concept，GPU 加速密钥派生，用于学术验证与防御性审计。

> **免责声明**：本项目仅用于安全研究、学术研究以及帮助用户验证自己的钱包是否由存在漏洞的软件生成。请勿将本工具用于非本人所有的钱包。作者不对任何滥用行为承担责任。

**在线演示**：本框架有一个实时运行的实例，可在项目[主页](https://easyhackcash.auths.cloud/easywallet)查看集群状态、扫描进度和各 POC 统计数据（当前为单节点部署）。

---

## 已复现漏洞

以下所有 POC 均对应已公开披露的 CVE 或安全公告，参考链接指向原始披露文档。

| POC ID | 漏洞描述 | 有效熵 | 派生速度 | 影响时间段 | 参考 |
|--------|---------|--------|---------|-----------|------|
| `dice_no_floor` | Coldcard 骰子路径 — 无最低熵阈值 | 2.585N bit | ~50,000/s | 2017 ~ present | [Coldcard 固件](https://github.com/Coldcard/firmware) |
| `yasmarang_bypass` | Coldcard Mk3 TRNG 回退至 Yasmarang PRNG | 32 bit | ~40,000/s | 2019 ~ 2020 | [公开披露](https://github.com/nwfella/coldcard-entropy-incident) |
| `tw_wasm_mt19937` | TrustWallet WASM MT19937 单 32-bit 种子 | 32 bit | ~8,000/s | 2022-11 ~ 2023-04 | [CVE-2023-31290](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31290) |
| `tw_ios_minstd` | TrustWallet iOS minstd_rand0 LCG | 31 bit | ~40,000/s | 2018-03 ~ 2018-12 | [CVE-2024-23660](https://milksad.info/posts/research-update-5/) |
| `ill_bloom` | CryptoJS WordArray.random() MWC PRNG | ~39 bit | ~8,000/s | 2012 ~ 2023 | [CVE-2026-71851](https://blog.coinspect.com/) |
| `mt19937_time_seed` | Python random.seed(time) 通用误用模式 | 27.7 bit | ~50,000/s | 2009 ~ 2015 | 通用模式 |
| `milksad_bx_seed` | Libbitcoin bx seed MT19937 32-bit 截断 | 32 bit | ~30,000/s | 2017 ~ 2023 | [CVE-2023-39910](https://milksad.info/disclosure.html) |
| `chosen_one` | 完整 2^256 随机采样（对照基准） | 256 bit | ~50,000/s | all time | BIP-39 标准 |

## 背景

比特币私钥是 256 位随机数，共有 2²⁵⁶（≈1.16×10⁷⁷）种可能值。正确生成时，暴力破解在计算上不可行。

然而，多个钱包实现被发现使用了非密码学 PRNG 或不充分的熵源进行密钥生成，将有效密钥空间缩减至 2³¹–2⁴⁰。这些缺陷已被公开利用，导致了上述 CVE 中记载的用户资产损失。

本框架使研究人员能够：
- **独立复现**已发表的漏洞发现
- **验证**特定钱包生成方法是否受影响
- **基准测试** GPU 加速密钥派生性能
- **审计**钱包生成算法的有效熵

---

## 性能基准

| 硬件 | 派生速度 | 覆盖 2³² 空间所需时间 |
|------|---------|---------------------|
| RTX 2060 Super ×1 | ~20K/s | ~58.2h |
| RTX 4060 Ti ×1 | ~50K/s | ~23.9h |
| B300 ×1 | ~175K/s | ~6.8h |
| B300 ×8 | ~1.4M/s | ~51min |
| B300 ×64 | ~11.2M/s | ~6.4min |

**熵风险分级**（BIP-39 要求 ≥128-bit 密码学安全熵）：

| 级别 | 有效熵 | 含义 |
|------|--------|------|
| Low | ≤ 80 bit | 理论上低于标准 |
| Medium | ≤ 50 bit | 专用硬件可覆盖 |
| High | ≤ 40 bit | 数天内可覆盖 |
| Critical | ≤ 30 bit | 数小时内可覆盖 |

---

## 快速开始

### 1. 获取 UTXO 地址集

**方式一：部署 Bitcoin 全节点**

1. 部署 Ubuntu 24 虚拟机
2. 执行 `dumpaddr/init.sh` 安装 Bitcoin Core 并同步区块链
3. 同步完成后运行 `python3 dumpaddr/main.py` 导出 UTXO 地址

**方式二：直接下载**

下载: https://mega.nz/file/T8BXBTyK#Vx2L3Qg1ue1ET5mgt5qvnNct2vgg_xy-tRUwTJh2p8o

将得到的 `utxo_addresses.set`（约 2.17GB）放入 `humanaction/addr/` 目录。

---

### 2. 环境准备

#### Windows 11

1. 安装 NVIDIA 驱动: https://www.nvidia.com/en-us/drivers/
2. 安装 VS Build Tools:
```
.\vs_BuildTools.exe --wait --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended
```
3. 安装 CUDA Toolkit 12.x: https://developer.nvidia.com/cuda-downloads
4. 安装 Rust: https://rustup.rs/
5. 重启后编译:
```bash
build.bat
cd dist
```

启动主控:
```bash
./btc-cuda-scanner.exe --role master --listenon 8877 --token mysecret --user admin --passwd admin
```

启动节点:
```bash
./btc-cuda-scanner.exe --role node --server 127.0.0.1:8877 --token mysecret
```

访问 http://localhost:8877/ 进入仪表板。

#### Linux

```bash
chmod +x build.sh
./build.sh
cd dist
./btc-cuda-scanner --role master --listenon 8877 --token mysecret --user admin --passwd admin
```

---

### 3. 仪表板

1. **POC Test**：根据所选 POC 算法生成助记词/私钥候选
2. **Scanner**：向节点分发任务，执行 GPU 加速地址匹配
3. **Hit Records**：查看匹配地址及其来源材料和元数据
4. **Benchmark**：使用已知测试向量验证检测准确性

---

### 4. 添加 POC

编辑 `humanaction/pocs/` 目录下的文件：
- `pocinfo.json` — POC 元数据
- `targets/<vendor>/<poc_id>/generator.py` — 密钥生成脚本

修改后在 POC Test 页面点击 **Reload** 生效。

---

## 架构

```
┌─────────────────────────────────────────────────┐
│   Master (--role master --listenon 8877)        │
│                                                 │
│   - POC 任务生成 (Python)                        │
│   - 任务队列分发                                  │
│   - 仪表板 (Web UI)                              │
│   - 节点管理 + 超时任务重试                        │
│                                                 │
│   Dashboard: http://master_ip:8877/             │
└──────────────────────┬──────────────────────────┘
                       │ HTTP Pull
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  Node A     │ │  Node B     │ │  Node N     │
│  RTX 2060S  │ │  RTX 4060Ti │ │  RTX 4090   │
│             │ │             │ │             │
│  - GPU 扫描  │ │  - GPU 扫描  │ │  - GPU 扫描  │
│  - 本地缓存  │ │  - 本地缓存  │ │  - 本地缓存  │
│  - 断线重试  │ │  - 断线重试  │ │  - 断线重试  │
└─────────────┘ └─────────────┘ └─────────────┘
```

---

## 相关工作

- [Milk Sad 披露](https://milksad.info/disclosure.html) — Libbitcoin bx seed 漏洞
- [Unciphered Randstorm](https://www.unciphered.com/disclosure-of-vulnerable-bitcoin-wallet-library-2/) — bitaddress.org 弱熵
- [Trust Wallet CVE-2023-31290](https://blog.secbit.io/p/trust-wallet-vulnerability-analysis/) — WASM MT19937 分析
- [Coldcard 熵事件](https://github.com/nwfella/coldcard-entropy-incident) — Yasmarang PRNG 回退

## 许可证

MIT License — 详见 [LICENSE](LICENSE)
