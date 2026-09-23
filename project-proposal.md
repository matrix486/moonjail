# MoonJail 项目设计与竞赛提案

## 1. 项目名称

**MoonJail — MoonBit 原生 Linux 最小权限沙箱**

## 2. 一句话介绍

> 一个为 MoonBit 生态提供 Linux 原生进程最小权限隔离、策略解释与可审计执行能力的开源项目。

## 3. 为什么现在需要它

MoonBit 已经拥有 LLM 客户端、Agent/workflow、CI runner、Web 框架、数据库、PTY 和 async process 等上层能力。这些项目开始运行外部命令、插件、构建脚本和 Agent 工具，但“进程能做什么”仍主要依赖宿主用户权限。

当前缺失的是一个可复用的 Linux 权限边界：

- 用 seccomp 限制 syscall；
- 用 Landlock 限制文件系统访问；
- 用 rlimit 限制 CPU、文件大小、打开文件数和进程数；
- 在执行前以结构化方式解释策略与内核支持情况；
- 在执行后输出稳定、可机器读取的结果。

这不是只服务 AI 的项目。潜在用户包括 coding agent、CI runner、插件宿主、在线判题、文档构建器、数据转换工具和任何需要执行第三方命令的 MoonBit 应用。

## 4. 候选项目竞争评分

评分统一为 0–5；除“实现难度”外越高越好，“实现难度”5 表示最难。优先级按 `生态缺口 > 创新性 > Demo 效果 > 开发难度`。

| 候选项目 | 已有竞争强度 | MoonBit 缺口 | 创新性 | 实现难度 | 展示效果 | 获奖概率 | 结论 |
|---|---:|---:|---:|---:|---:|---:|---|
| 通用 Agent Framework | 5 | 1 | 1 | 3 | 4 | 1 | 禁止：已有多套活跃实现 |
| AI Evaluation Framework | 3 | 2 | 3 | 3 | 4 | 2 | 已有 faceoff、agentcheck、telemetry 等项目群 |
| Web/WASM UI 框架 | 5 | 1 | 2 | 5 | 5 | 1 | 禁止：Rabbita/Luna/MoUI/Proton 等成熟 |
| eBPF 可观测性 SDK | 2 | 4 | 4 | 5 | 5 | 4 | 有 libbpf binding，可作为未来扩展但 MVP 风险高 |
| systemd 服务运行时 | 1 | 5 | 3 | 3 | 3 | 4 | 缺口明确，但 Demo 与跨场景价值较弱 |
| **MoonJail Linux 沙箱** | **1** | **5** | **5** | **4** | **5** | **5** | **最终选择** |

### 必答竞争问题

1. **Mooncake 是否已有类似项目？** 有相邻项目 AegisRun、内存 sandbox、process manager 和 libbpf binding，但没有 seccomp + Landlock + rlimit 的 MoonBit 原生进程沙箱。
2. **GitHub 是否已有类似 MoonBit 项目？** 精确搜索没有发现 MoonBit seccomp/Landlock 实现。
3. **已有相邻项目时为什么仍值得存在？** AegisRun 要求工具进入 Wasm/Wasmtime，且 runtime 使用 Rust；MoonJail 面向任意 Linux ELF/脚本进程，以内核隔离原语执行，无需重编译为 Wasm。
4. **是否属于生态新增能力？** 是。它把 MoonBit 的 async/process/FFI 基础向“安全执行第三方代码”推进一层。
5. **是否符合赛事宗旨？** 是。项目是可复用基础设施，边界明确，能测试、能演示、能发布 Mooncakes，并具有长期维护路线。

## 5. 与已有项目区别

```makefile
已有项目:

AegisRun = MoonBit 策略判断 + Rust/Wasmtime WASI 工具沙箱
moonbit_libbpf = libbpf 的底层 eBPF 绑定
sennenki/process = 通用进程创建与管理
bm2 = Bun/Node.js 进程监督器
mizchi/sandbox = 内存 VFS/POSIX 模拟

本项目:

MoonJail = 纯 MoonBit 公共策略与编译器 + 极薄 C syscall shim，
           对任意 Linux 原生子进程应用 seccomp、Landlock、no_new_privs 和 rlimit，
           提供 explain/compile/run 与结构化审计结果。
```

项目不会复制 libbpf、process manager、Wasm runtime 或 Agent framework。若后续接入现有 process API，将明确标注为集成，而不是取代。

## 6. 技术架构

### Architecture Diagram

```text
Policy Builder / JSON Profile
            |
            v
     Policy Validation
      /      |       \
     v       v        v
Seccomp   Landlock   RLimit
Compiler   Planner   Planner
     \       |        /
      v      v       v
        SandboxPlan
        /         \
       v           v
 explain/json   Linux Runtime
                   |
        no_new_privs -> landlock -> rlimit -> seccomp -> exec
                   |
                   v
              SandboxResult
```

### Modules

| 包 | 职责 |
|---|---|
| root `moonjail` | 公共类型、Policy builder、presets、validation |
| root `seccomp.mbt` | classic-BPF 指令模型、syscall dispatch compiler、静态 verifier、反汇编 |
| root `policy.mbt` / `validate.mbt` | 文件系统 rights、策略校验与资源限制 |
| `runtime` | Linux capability probe、apply plan、受限进程启动；非 Linux 返回 typed UnsupportedPlatform |
| root `profile.mbt` | JSON profile 的解析、版本化与诊断 |
| `cmd/moonjail` | `check`、`explain`、`explain-profile`、`run`、`demo` CLI |
| `examples/*` | 可编辑的版本化策略文件；AI tool 与 build step 的专门示例列为后续集成任务 |

### Data Flow

1. 用户通过 builder 或 JSON 创建 `Policy`。
2. validator 检查空规则、重复 syscall、未知 syscall、无效路径字符与非法资源限额；当前不做路径规范化或自动 rights 合并。
3. compiler 生成 `SandboxPlan`：BPF instructions、Landlock rules、rlimits 和最低内核能力。
4. `explain` 可在不执行命令时展示允许/拒绝面和降级风险。
5. Linux runtime fork 子进程，在 exec 前按固定顺序施加限制。
6. 父进程按墙钟超时等待，收集退出、signal、超时或设置失败状态，并记录 Landlock ABI，生成 `SandboxResult`。

### API Design

```moonbit
let policy = @moonjail.Policy::from_profile(ConsoleTool)
  .allow_read("./workspace")
  .allow_write("./workspace/out")
  .limit_cpu(2)
  .limit_memory(134217728L)

let plan = @moonjail.compile(policy, X86_64)
let report = @runtime.run(plan, "./tool", args=["input.json"], timeout_ms=30000)
```

设计原则：

- deny-by-default preset 明确命名；
- 策略先编译为纯数据 `SandboxPlan`，便于测试和 dry-run；
- 路径策略要求 Landlock ABI 3+，能力缺失时 fail-closed；
- 公共具体类型由 facade 或非 internal 公共包持有；
- runtime error 使用 typed error，不把策略拒绝与基础设施失败混为一谈。

## 7. MVP 范围

第一阶段必须完成：

### 核心功能

- 版本化 Policy 与 builder API；
- x86_64 / aarch64 syscall 元数据的最小集合；
- seccomp classic-BPF compiler、verifier、disassembler；
- Landlock read/write/execute 规则计划与 ABI probe；
- `PR_SET_NO_NEW_PRIVS`、rlimit 与 seccomp/Landlock apply；
- Linux 子进程执行、墙钟超时与结构化结果；
- 非 Linux 上可运行的 compile/explain，runtime 明确报不支持。

### Demo

- 允许读取 workspace 内输入；
- 拒绝读取 `/etc/passwd`；
- 拒绝创建网络 socket；
- 允许同一个工具在放宽策略后成功；
- 输出策略解释、kernel capability 与 JSON 执行结果。

### Tests

- BPF jump 与 instruction limit；
- syscall allow/deny 编译快照；
- 不同 architecture audit value；
- Landlock 读、写、执行拒绝与 ABI 缺失时 fail-closed；
- profile JSON round-trip 与错误诊断；
- Linux CI integration tests：文件、网络、rlimit 与 exec；
- `moon check --target all` 覆盖纯逻辑包，native Linux 覆盖 runtime。

### Documentation

- README：目标、威胁模型、安装、快速开始、支持矩阵；
- `SECURITY.md`：不保证的边界、内核版本与 fail-closed 行为；
- API docs 与可执行 `README.mbt.md` 示例；
- `CONTRIBUTING.md`、架构说明与开发记录；
- 来源与许可证说明。

### 非目标

- 容器 runtime；
- 完整 namespace/cgroup 编排；
- Windows/macOS 沙箱；
- 恶意内核或 root 对手；
- Wasm runtime、Agent framework 或通用 process supervisor。

## 8. Hackathon 三分钟 Demo

### 0–30 秒：问题

- 展示 MoonBit Agent/CI runner 执行一个第三方工具。
- 工具正常读取输入，但也尝试读取 `/etc/passwd` 和连接外网。
- 点明普通 `process.spawn` 只负责启动，不提供最小权限边界。

### 30–120 秒：代码

- 展示约 10 行 Policy builder 与可编辑 JSON 策略。
- 运行 `moonjail explain`：终端显示 syscall、文件 rights、rlimit 和 kernel capability。
- 运行同一工具：workspace 读取成功，敏感文件与网络被内核拒绝。
- 展示 JSON result 与 stderr，区分受限命令的非零退出与沙箱设置失败。

### 120–180 秒：效果

- 为同一个文件读取命令补一条授权路径，展示从拒绝到允许的变化。
- 展示 Linux CI 四类 integration tests 全绿。
- 最后展示生态接入图：Agent、CI、plugin host、online judge 都复用同一个 `SandboxPlan` API。

## 9. 交付与长期路线

### v0.1 MVP

seccomp + Landlock + rlimit + CLI + tests + docs。

### v0.2

- user namespace 与 mount namespace；
- cgroup v2 CPU/memory/pids；
- policy diff 与 profile inheritance；
- async process integration。

### v0.3

- seccomp user notification；
- OpenTelemetry/audit exporter；
- 与 `moonbitlang/workflow`、CI runner、MCP tool host 的 adapter。

## 10. 风险控制

| 风险 | 处理 |
|---|---|
| 当前开发机是 Windows | 纯策略/编译器跨平台测试；Linux runtime 在用户提供的远程 Linux 主机验证 |
| Landlock 内核版本差异 | capability probe + 明确 fail-closed / explicit degraded mode |
| syscall 表随架构变化 | 元数据独立包、生成来源记录、conformance tests |
| 安全项目容易过度承诺 | 明确威胁模型，不宣称容器级或 root 级隔离 |
| FFI 侵占 MoonBit 主体 | C shim 只做 syscall 参数桥接；策略、编译、验证、CLI 逻辑均在 MoonBit |

## 11. 赛事符合性

- 原创项目，不是现有 MoonBit 包移植；
- MoonBit 为主要实现语言；
- MoonBit 为策略与编译器主体，C 仅封装 Linux syscall/进程启动；不以代码行数充当验收指标；
- Apache-2.0 许可证；
- CI 覆盖 check/build/test 与 Linux integration；
- 提供可运行 demo、核心测试、README 与 Mooncakes 发布准备；
- 仓库保留真实阶段性提交与开发记录，不做空提交或机械拆分。
