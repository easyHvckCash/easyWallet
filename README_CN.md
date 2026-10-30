# easyWallet

> ⚠️ **安全事件说明**：在与 AI 协作编码过程中，我明确要求对测试助记词进行脱敏处理，但 AI 仍将完整助记词嵌入到了前端代码的 placeholder 示例中（i18n 文件）。虽然是测试用途的助记词，但这暴露了 AI 辅助开发中对敏感数据处理的不可控风险——提示词级别的约束并不可靠。[问题完整复盘分析](https://easyhvckcash.auths.cloud/zh/notes/first-time-hacked)

排名第一的开源私钥破解框架。全面集成公开 POC，GPU 加速，领先的弱熵钱包利用方案。

官网: https://easyhackcash.auths.cloud/easywallet （实时展示真实运行中的集群数据，目前由一台家用小台式在跑）

---

## 已公开 POC

| POC ID | 名称 | 严重级别 | 有效熵 | 速度 | 覆盖范围 | 参考 |
|--------|------|----------|--------|------|----------|------|
| `dice_no_floor` | Coldcard 骰子路径无熵下限 | defense-in-depth failure | 2.585N bit | ~50,000/s | 2017 ~ present | [Coldcard 固件源码](https://github.com/Coldcard/firmware) |
| `yasmarang_bypass` | Coldcard TRNG 错链 Yasmarang | critical (~594 BTC stolen) | 32 bit | ~40,000/s | 2019 ~ 2020 | [公开披露](https://github.com/nwfella/coldcard-entropy-incident) |
| `tw_wasm_mt19937` | TrustWallet WASM MT19937 弱种子 | critical (32 bit) | 32 bit | ~8,000/s | 2022-11 ~ 2023-04 | [CVE-2023-31290](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31290) |
| `tw_ios_minstd` | TrustWallet iOS minstd_rand0 LCG | critical (31 bit, 2023-07 被利用) | 31 bit | ~40,000/s | 2018-03 ~ 2018-12 | [CVE-2024-23660](https://milksad.info/posts/research-update-5/) |
| `ill_bloom` | Blockchain.info CryptoJS MWC PRNG | critical (39-40 bit, $5M+ stolen) | ~39 bit | ~8,000/s | 2012 ~ 2023 | [CVE-2026-71851](https://blog.coinspect.com/) |
| `mt19937_time_seed` | Python random.seed(time) 通用模式 | critical (27.7 bit) | 27.7 bit | ~50,000/s | 2009 ~ 2015 | 通用误用模式 |
| `milksad_bx_seed` | Libbitcoin bx seed MT19937 | critical (32 bit, $900K+, 227K wallets) | 32 bit | ~30,000/s | 2017 ~ 2023 | [Milk Sad CVE-2023-39910](https://milksad.info/disclosure.html) |
| `chosen_one` | 天选之子 (全 2^256 随机采样) | none (不可破解) | 256 bit | ~50,000/s | all time | BIP-39 标准随机 |

更多私有 POC 未列出。

## 为什么这是有意义的工作

比特币私钥是 256 位随机数，存在 2²⁵⁶（≈1.16×10⁷⁷）种可能——远超可观测宇宙中的原子总数。如果密钥真正随机，暴力破解在物理上不可能。

但现实中，没有人手动挑选 256 个随机位。每个人都依赖钱包软件生成私钥。问题在于：**部分钱包产品使用了傻瓜代码实现密钥生成**，将理论上的 2²⁵⁶ 空间压缩到了 2³² 甚至更小。

通过枚举这些极小的空间，攻击者可以重建每个受影响钱包的私钥并窃取资金。这不是理论——上述 POC 对应的多起公开事件已证明攻击有效。

不得不佩服那些先行者——他们既有足够的洞察力识别这些缺陷，也有绝对的执行力去行动。但为时不晚。本项目的目标是：**让一台家用电脑也能加入这场游戏**。借助 GPU 加速和分布式计算，单张 RTX 4060 Ti 即可在 24 小时内扫完 2³² 全密钥空间。

---

## 本项目运算效率

| 硬件 | 速度 | 2³² 全空间覆盖时间 |
|------|------|------------------|
| RTX 2060 Super ×1 | ~20K/s | ~58.2h |
| RTX 4060 Ti ×1 | ~50K/s | ~23.9h |
| B300 ×1 | ~175K/s | ~6.8h |
| B300 ×8 | ~1.4M/s | ~51min |
| B300 ×64 | ~11.2M/s | ~6.4min |

**POC 严重性定级**：基于生成密钥的有效熵（BIP-39 要求至少 128-bit 密码学安全随机熵）

| 级别 | 有效熵 | 风险 |
|------|--------|------|
| Low | ≤ 80 bit | 理论上可被攻击 |
| Medium | ≤ 50 bit | 专用硬件可行 |
| High | ≤ 40 bit | 数天内可实际攻击 |
| Critical | ≤ 30 bit | 数小时内可利用 |

**6 个月攻击面**：

| 硬件 | 可覆盖空间 |
|------|-----------|
| B300 ×1 | ≤ 2⁴¹ 不安全 |
| B300 ×8 | ≤ 2⁴⁴ 不安全 |
| B300 ×64 | ≤ 2⁴⁷ 不安全 |

---

## 快速开始

### 2.1 获取 UTXO 地址集

**方式一：部署 Bitcoin 节点自行导出**

1. 部署 Ubuntu 24 虚拟机
2. 执行 `dumpaddr/init.sh` 安装 Bitcoin Core 并同步区块链
3. 同步完成后运行 `python3 dumpaddr/main.py` 导出 UTXO 地址

**方式二：直接下载（推荐）**

下载地址: https://mega.nz/file/T8BXBTyK#Vx2L3Qg1ue1ET5mgt5qvnNct2vgg_xy-tRUwTJh2p8o

最终你会得到 `utxo_addresses.set` 文件（约 2.17GB），将其放置到 `humanaction/addr/` 目录下。

---

### 2.2 环境准备

#### 2.2.1 Windows 11

安装 NVIDIA 驱动:
https://www.nvidia.com/en-us/drivers/ 搜索你的 GPU 型号

安装 VS Build Tools（先装这个，再装 CUDA）:
下载: https://aka.ms/vs/17/release/vs_BuildTools.exe
```
.\vs_BuildTools.exe --wait --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended
```

安装 CUDA Toolkit 12.x:
下载: https://developer.nvidia.com/cuda-downloads （选择完整安装，不要快速安装）

安装 Rust 工具链:
https://rustup.rs/

重启机器。

编译：
```bash
build.bat
cd dist
```

开启两个 CMD 窗口，分别执行：

Master（主控）:
```bash
./btc-cuda-scanner.exe --role master --listenon 8877 --token mysecret --user admin --passwd admin
```

Node（工作节点）:
```bash
./btc-cuda-scanner.exe --role node --server 127.0.0.1:8877 --token mysecret
```

**单机快速测试（推荐）：**

```bash
run.bat
```

`run.bat` 是一键脚本，自动结束已运行的旧进程，重新编译全部组件（CUDA PTX + Vue 前端 + Rust），然后在本机启动一个 Master 节点和一个 Worker 节点。适合本地快速验证——执行后直接访问 http://localhost:8877/ 即可。

打开浏览器访问 http://localhost:8877/ 进入仪表板。

#### 2.2.2 Linux

Rust 已支持 Linux 编译，但尚未实测。欢迎补充测试结果。

```bash
chmod +x build.sh
./build.sh
cd dist
./btc-cuda-scanner --role master --listenon 8877 --token mysecret --user admin --passwd admin
```

---

### 2.3 面板使用

1. **POC Test 页面**：点击对应 POC 的 Start 按钮，Master 会根据 POC 代码批量生成助记词或私钥任务文件
2. **Scanner 页面**：点击 "Start Dispatch"（类似总出水闸），开启后 Node 才能拉取到任务。针对已接入的 Node，可切换 GPU 或 CPU 模式运行，也可以定向暂停/启动特定节点参与运算。新接入的 Node 默认处于暂停状态，需手动启动
3. **Hit Records 页面**：产生命中后，在此查看所有发现的弱熵地址，包含来源助记词/私钥、关联 POC、发现时间等
4. **Benchmark 页面**：如果你对扫描准确性存疑，可输入已知有资产的助记词或私钥，选择一个暂停状态的 Node 执行基准测试，验证 hit 检测是否正确

---

### 2.4 增删改 POC

修改 `humanaction/pocs/` 目录下的文件即可：
- `pocinfo.json` — POC 元数据配置
- `targets/<vendor>/<poc_id>/generator.py` — 生成器脚本

新增 POC 只需添加对应的 generator.py 并在 pocinfo.json 中注册。

修改完成后，需在 POC Test 面板点击 **Reload** 按钮使配置生效。如果 POC 运行报错，可点击对应 POC 的 **Details** 按钮查看错误日志。

---

## 架构

```
┌─────────────────────────────────────────────────┐
│   Master (--role master --listenon 8877)        │
│                                                 │
│   - POC 任务生成 (Python)                        │
│   - 任务队列分发                                  │
│   - 集群仪表板 (统一面板)                          │
│   - 节点状态管理 + 超时任务重试                     │
│                                                 │
│   Dashboard: http://master_ip:8877/             │
└──────────────────────┬──────────────────────────┘
                       │ HTTP Pull（节点主动拉取）
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

## 致谢

全程由 Claude Opus 4.6 开发，非原始人力开发。

## 许可证

MIT License — 详见 [LICENSE](bitcoin/win11/LICENSE)
