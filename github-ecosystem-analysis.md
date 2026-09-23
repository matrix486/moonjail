# GitHub MoonBit 生态调研（2026-09-23）

## 1. 检索范围

执行了以下 GitHub repository / issue 查询：

- `language:MoonBit`
- `topic:moonbit`
- `moonbit in:name,description`
- `moonbitlang`、`moonbit-community`
- `awesome-moonbit`
- `moonbit seccomp`、`moonbit landlock`、`moonbit systemd`
- 官方与社区组织中的 open issue：`native FFI`、`process Linux`、`sandbox`、`Linux`

检索时 `language:MoonBit` 约 2,773 个仓库，`topic:moonbit` 约 335 个仓库，说明生态已经从“空白期”进入快速扩张期，不能再靠泛方向判断创新性。

## 2. 官方与社区基础设施

| 仓库 | Star / issue（调研时） | 最近活动 | 作用与判断 |
|---|---:|---|---|
| `moonbitlang/moonbit-docs` | 2,436 / 38 | 2026-09-22 | 官方语言与工具链文档，仍快速演进 |
| `moonbitlang/core` | 1,216 / 105 | 2026-09-23 | 标准库；README 明确 API 仍会变化 |
| `moonbitlang/moonbit-compiler` | 705 / 7 | 2026-09-21 | 编译器；roadmap 包括继续开放更多工具 |
| `moonbitlang/moon` | 422 / 139 | 2026-09-22 | 构建系统与包管理器 |
| `moonbitlang/awesome-moonbit` | 157 / 0 | 2026-09-11 | 官方精选生态索引 |
| `moonbitlang/async` | 68 / 30 | 2026-09-22 | 文件、进程、网络、socket、HTTP 的异步基础设施 |
| `moonbitlang/openseek` | 88 / 101 | 2026-09-23 | MoonBit 编写的 coding agent，显示 AI 方向已有官方级项目 |
| `moonbit-community/rabbita` | 129 / 21 | 2026-09-22 | Web UI 框架 |
| `moonbit-community` 组织 | 325 个仓库 | 持续更新 | 已覆盖 desktop、PTY、结构化搜索、BSON、UI 等多个方向 |

## 3. 高热项目与生态形态

`language:MoonBit` Star 排名前列包括：

- `mizchi/actrun`（668）：GitHub Actions 兼容 runner；
- `nikivdev/mbt`（488）：MoonBit 工具与库集合；
- `trkbt10/indexion`（151）：源码探索与文档工具；
- `moonbit-community/rabbita`（129）：Web UI；
- `mizchi/markdown.mbt`（102）：增量 Markdown；
- `oboard/mocket`（95）：Web 框架；
- `mizchi/crater`（74）：浏览器/CSS layout 相关；
- `pku-dppl/TAPL-in-MoonBit`（73）：PL 教学与实现。

结论：Web、语言工具、Agent、解析器、UI 和常用基础库已产生清晰头部项目；“再做一个普通框架”很难形成独立生态价值。

## 4. Awesome MoonBit 覆盖面

官方 `awesome-moonbit` 已列出：

- Foundations：core、x、async、quickcheck、parser、regexp；
- Text/Data：TOML、YAML、CSV、CommonMark、XML、pretty-printer、压缩与 Unicode；
- Application：Proton、Rabbita、Respo、Luna、Mocket、Mars、TUI、MoUI、Egui；
- Systems：TTY、PTY、FFI utilities、JS bindings、Web APIs、SQLite、Postgres、WIT、Extism PDK；
- Graphics/Media：颜色、图像 codec、WebGPU、物理引擎、diagram；
- Developer tools：Moon、MoonLex、MoonYacc、protobuf、tree-sitter、GitHub Action、Neovim；
- Showcase：Wasm VM、C11 compiler、NES emulator、full-stack demo。

该清单没有 seccomp、Landlock、Linux capability、cgroup 或原生进程 sandbox 条目。

## 5. Roadmap、TODO 与 issue 信号

### 官方 roadmap

- MoonBit compiler roadmap 强调继续开放编译工具，说明编译器方向会持续由官方投入。
- MoonLLVM roadmap 已列出 C compiler、assembler/linker、bitcode、LLVM IR parser、x86_64/aarch64/riscv64；不宜重复选编译后端大题。
- core changelog 显示 native async、process、FFI 与多后端能力仍高速演进，适合在其上建设 Linux 原生库。

### 相关 open issues / TODO

- `moonbitlang/async#571`：Linux epoll fd 复用正确性；说明 native Linux runtime 正在被真实使用并仍需生态层封装。
- `moonbitlang/async#442`：native async correctness follow-ups。
- `moonbit-community/Community-Tasks#96`：类 Unix signal handling 库仍是开放任务。
- `moonbit-community/Community-Tasks#71`：Process 库任务，已有实现但生态仍在补齐。
- `moonbitlang/openseek/todo.md`：列出 CLI 语义验证、结构化 shell policy、manifest guardrail 等需求；这说明工具安全是需求，但这些 TODO 针对 Agent 自身，不等同于内核级进程隔离。

### 精确空白搜索

- `language:MoonBit seccomp`：没有 MoonBit 实现命中。
- `language:MoonBit landlock`：没有 MoonBit 实现命中。
- `moonbit seccomp in:name,description,readme` 返回的少量结果均为无关 awesome/star 列表或其他语言项目。
- `moonbit systemd` 有大量文本噪声，但没有 MoonBit systemd SDK。

## 6. 竞争项目核查

### AegisRun

- 仓库：`tuya-me/AegisRun`，调研时 0 Star、97 commits、0 open issues。
- 架构：约 3,600 行 MoonBit 策略引擎 + 约 1,800 行 Rust runtime；以 Wasmtime/WASI 执行已编译为 Wasm 的工具。
- API：MoonBit `AegisRun::new(...).check_domain(...)`；Rust CLI 提供 scan、sandbox、audit、policy、tool registry 和 Web 管理面板。
- 不重叠依据：MoonJail 约束任意 Linux 原生进程，使用内核 seccomp/Landlock；不要求工具改编为 Wasm，不使用 Rust/Wasmtime，也不实现 Agent 工具市场和 Web 控制台。

### moonbit_libbpf

- Registry：`hevienz/moonbit_libbpf@0.10.0`，39 downloads，2026-03-22 发布。
- 定位：libbpf binding，用于加载与管理 eBPF 程序。
- 不重叠依据：seccomp 使用 classic BPF filter ABI，MoonJail 的公共 API 是 `Policy -> SandboxPlan -> apply/exec`；不会包装 libbpf object/map/probe API。

### 进程与文件系统项目

- `sennenki/process`：通用 spawn/manage；
- `chensuiyi/bm2`：Bun/Node 的 Linux supervisor；
- `mizchi/fswatch`：跨平台文件变化通知。

它们不提供 syscall allowlist、filesystem access rights、`no_new_privs`、resource limits 的统一策略模型。

## 7. GitHub 生态空白结论

MoonBit 原生 Linux 系统编程开始具备 async、process、TTY/PTY、FFI、数据库和桌面基础，但缺少“**将不可信原生子进程限制在最小权限内**”的可复用层。该空白同时满足：

- 不是简单算法或数据结构；
- 不是语言移植包装；
- 能推动 Agent、CI runner、插件宿主、在线判题和服务进程等上层项目；
- 能通过真实 Linux 内核行为做强 Demo；
- 可以长期扩展 user namespace、cgroup v2、seccomp notify 和审计后端。

## 8. 主要来源

- [MoonBit compiler](https://github.com/moonbitlang/moonbit-compiler)
- [MoonBit core](https://github.com/moonbitlang/core)
- [Moon build tool](https://github.com/moonbitlang/moon)
- [MoonBit async](https://github.com/moonbitlang/async)
- [MoonBit community repositories](https://github.com/orgs/moonbit-community/repositories)
- [Awesome MoonBit](https://github.com/moonbitlang/awesome-moonbit)
- [MoonLLVM roadmap](https://github.com/moonbitlang/MoonLLVM)
- [OpenSeek TODO](https://github.com/moonbitlang/openseek/blob/main/todo.md)
- [AegisRun](https://github.com/tuya-me/aegisrun)

