# Mooncakes.io 生态调研（2026-09-23）

## 1. 调研口径

- 数据源：Mooncakes 首页、`/api/v0/search`、各模块文档页。
- 检索词：`AI`、`agent`、`workflow`、`RAG`、`MCP`、`evaluation`、`prompt`、`parser`、`compiler`、`database`、`web`、`image`、`audio`、`crypto`、`testing`、`benchmark`、`devtool`、`wasm`、`visualization`，并追加 Linux 方向的 `seccomp`、`sandbox`、`systemd`、`journald`、`inotify`、`pidfd`、`cgroup`、`namespace`、`capability`、`landlock`、`fanotify`、`daemon`。
- Mooncakes 当前不展示 GitHub Star；下表用累计下载量作为实际使用信号，GitHub Star 单独记录在 `github-ecosystem-analysis.md`。
- “最近更新”取当前版本的 registry 发布时间；“活跃”定义为 90 天内有版本发布或对应仓库近期有提交。
- 本报告不是全站包清单，而是围绕候选方向的高相关、代表性和高使用量模块审计。

## 2. 代表性模块清单

| 方向 | 项目（作者） | 当前版本 / 下载 | 最近发布 | 功能与 API 形态 | 活跃性 | 与候选项目重叠 |
|---|---|---:|---|---|---|---|
| LLM | `mizchi/llm` | 0.3.2 / 151,089 | 2026-08-15 | 纯 MoonBit LLM 客户端，统一消息、流式输出和工具调用 | 活跃 | 无 |
| Agent | `weopqrst/agent` | 0.5.1 / 42 | 2026-08-19 | LangChain 风格 `Runnable`、Prompt、Memory、Tool、AgentExecutor | 活跃 | 无；说明 Agent 框架已撞车 |
| Agent | `Lfan-ke/moonkoog` | 0.4.1 / 34 | 2026-09-13 | Koog 移植，类型化消息、工具注册和单轮 Agent loop | 活跃 | 无；再次排除 Agent 框架 |
| Workflow | `moonbitlang/workflow` | 0.7.2 / 12,080 | 2026-09-22 | `Runner` / `Workflow`、并发门控、typed outcome、journal replay | 高度活跃 | 无；工作流方向已成熟 |
| Workflow | `mizchi/bitflow` | 0.4.1 / 151,689 | 2026-04-04 | Starlark 子集、DAG 执行、缓存计划 | 有使用基础 | 无；普通 DAG 引擎撞车 |
| MCP | `colmugx/mcp` | 0.17.5 / 403 | 2026-09-06 | 类型安全 Client/Server，STDIO 与 HTTP 双传输 | 活跃 | 无；MCP SDK 已成熟 |
| MCP | `cogna-dev/mcp-sdk` | 0.1.0 / 66 | 2026-04-16 | MCP Server、工具、资源、Prompt、Sampling、Elicitation | 更新较早 | 无；仍构成功能重叠 |
| RAG | `trkbt10/vcdb` | 0.3.2 / 603 | 2026-07-20 | 多 ANN 算法的向量数据库 | 活跃 | 无；RAG 基础组件已有 |
| Parser | `moonbitlang/parser` | 0.4.0 / 162,484 | 2026-09-21 | MoonBit AST、源码 parser、`parse_file` / `parse_string` | 高度活跃 | 无 |
| Parser | `Nanaloveyuki/parsec` | 0.1.3 / 359 | 2026-08-09 | token-generic parser combinator，`map` / `flat_map` / `then` | 活跃 | 无；通用 parser combinator 撞车 |
| Compiler | `Kaida-Amethyst/MoonLLVM` | 0.1.18 / 2,663 | 2026-09-10 | LLVM 风格 IR 与编译基础设施 | 活跃 | 无 |
| Compiler | `Milky2018/regalloc` | 0.16.0 / 221 | 2026-09-16 | 目标无关寄存器分配 | 高度活跃 | 无；编译后端基础件已有 |
| Database | `Lfan-ke/moondb` | 0.1.8 / 927 | 2026-09-13 | Driver↔query 的标准接口层 | 活跃 | 无 |
| Database | `oboard/morm` | 0.4.3 / 545 | 2026-09-13 | 类型查询、代码生成、多数据库 ORM | 活跃 | 无；普通 ORM 撞车 |
| Web | `moonbit-community/rabbita` | 0.16.2 / 75,169 | 2026-09-20 | 函数式 Web UI 框架 | 高度活跃 | 无；前端框架已有强项目 |
| Web | `bikallem/webapi` | 0.5.0 / 572 | 2026-04-06 | DOM、fetch、HTML、XHR、URL、SVG 等浏览器绑定 | 有维护 | 无 |
| Image | `mizchi/image` | 0.4.3 / 19,934 | 2026-07-20 | PNG/BMP/JPEG 编解码，GIF/WebP/ICO/AVIF 编码与 resize | 活跃 | 无；通用图片处理撞车 |
| Audio | `Milky2018/moon_cpal` | 0.11.8 / 7,871 | 2026-08-03 | RustAudio/cpal 子集移植，原生音频 I/O | 活跃 | 无 |
| Audio | `Milky2018/moon_rodio` | 0.3.5 / 6,632 | 2026-09-07 | 播放 pipeline、source effect、多格式解码 | 活跃 | 无；音频播放层已有 |
| Crypto | `cc06b/mooncry` | 0.95.0 / 675 | 2026-09-20 | 哈希、AEAD、公钥、国密与后量子算法集合 | 高度活跃 | 无；密码原语方向严重撞车 |
| Testing | `moonbitlang/quickcheck` | 0.14.0 / 177,275 | 2026-05-23 | 属性测试与随机生成 | 成熟 | 无；普通测试框架撞车 |
| Testing | `Magic486/moon_mutest` | 0.1.7 / 40 | 2026-07-12 | MoonBit mutation testing 工具 | 活跃 | 无；变异测试也已存在 |
| Benchmark | `Luna-Flow/mare_mark` | 0.3.0 / 53 | 2026-07-15 | 可复现实验、统计比较、调优与自包含报告 | 活跃 | 无；benchmark 工具撞车 |
| Devtool | `mizchi/actrun` | 0.32.0 / 618 | 2026-09-18 | GitHub Actions 兼容的本地 runner | 高度活跃 | 无 |
| Devtool | `justjavac/cdp` | 0.1.9 / 5,052 | 2026-07-24 | Chrome DevTools Protocol 客户端 | 活跃 | 无 |
| WASM | `mizchi/oci_wasm` | 0.5.0 / 64,603 | 2026-02-11 | WebAssembly OCI registry 客户端 | 有大量使用 | 无 |
| WASM | `Milky2018/wasmoon` | 0.16.0 / 166 | 2026-09-16 | 纯 MoonBit Wasm runtime 及 JIT 相关包 | 高度活跃 | 无；Wasm runtime 撞车 |
| Visualization | `Xpeng/mooncharts` | 0.8.0 / 53 | 2026-07-07 | 原生 SVG 柱/线/饼/散点图 | 活跃 | 无；普通图表库撞车 |
| Linux/eBPF | `hevienz/moonbit_libbpf` | 0.10.0 / 39 | 2026-03-22 | libbpf 的底层 MoonBit 绑定 | 近半年无新版 | 相邻但不重叠：它是 eBPF loader 绑定，不是进程沙箱 |
| Linux/fs | `mizchi/fswatch` | 0.2.1 / 1,248 | 2026-06-29 | Linux inotify、macOS FSEvents、轮询 fallback | 活跃 | 无；文件监听撞车 |
| Linux/process | `sennenki/process` | 0.1.0 / 36 | 2026-01-31 | 进程创建与管理 | 活跃度不明 | 相邻：MoonJail 可基于/兼容进程层，但不重复 spawn API |
| Linux/process | `chensuiyi/bm2` | 0.4.1 / 53 | 2026-08-31 | Bun/Node.js 的 Linux 进程管理器 | 活跃 | 相邻：服务监督，不提供内核最小权限 |
| Sandbox | `tuya-me/aegisrun` | 0.9.3 / 41 | 2026-07-17 | MoonBit 策略引擎 + Rust/Wasmtime WASI 沙箱 | 活跃 | 部分相邻；隔离对象、后端、API 均不同 |

## 3. API 与竞争结论

### 已成熟或已有强竞争，禁止选择

1. **Agent / RAG / MCP / workflow**：已有 `mizchi/llm`、`weopqrst/agent`、`moonkoog`、`moonbitlang/workflow`、两套 MCP SDK 与向量数据库。继续做同类框架会违反“高度一致且活跃维护则禁止选择”。
2. **Parser / compiler 基础件**：官方 parser、parser combinator、MoonLLVM、MilkIR、regalloc 均在活跃迭代。
3. **Web / image / audio / visualization**：已有高下载量 Web UI、图像 codec、音频 I/O/播放和多套 SVG 图表。
4. **Testing / benchmark / tracing**：QuickCheck、mutation testing、benchmark、OpenTelemetry、结构化 tracing 已覆盖常见需求。
5. **数据库 / crypto / WASM runtime**：接口层、ORM、向量库、广覆盖 crypto 套件与 Wasm runtime 已形成项目群。

### 仍然存在的 Linux 基础能力空白

对 `seccomp`、`Landlock`、`fanotify` 的 Mooncakes 搜索为零；`systemd`、`journald` 搜索没有命中对应 SDK。现有 sandbox 项目是：

- `mizchi/sandbox`：内存虚拟文件系统和 POSIX 模拟，不约束真实 Linux 进程；
- `Haoxincode/moonbash`：纯内存 shell sandbox，不调用 Linux 隔离原语；
- `tuya-me/aegisrun`：把工具编译为 Wasm，由 Rust/Wasmtime 执行；
- `moonbit_libbpf`：libbpf 的低层绑定，面向 eBPF 对象加载，不提供 seccomp classic-BPF 策略、Landlock 或受限进程启动。

因此“**MoonBit 原生 Linux 进程最小权限沙箱**”是当前 registry 中没有等价项目的新增能力。

## 4. 最终防撞车判断

`MoonJail` 不做 Wasm runtime、不做通用进程管理器、不做 eBPF loader。它提供：

- 可检查的策略模型；
- seccomp classic-BPF 编译与静态验证；
- Landlock 文件系统规则；
- `no_new_privs`、resource limit 与 Linux capability 探测；
- 原生子进程的 apply-and-exec；
- dry-run / explain / JSON 审计结果。

与现有项目关系是“复用底层生态并新增 Linux 隔离能力”，不是重复建设。

## 5. 主要来源

- [Mooncakes 首页](https://mooncakes.io/)
- [Mooncakes 搜索 API 说明](https://github.com/moonbitlang/mooncakes.io)
- [moonbitlang/workflow](https://mooncakes.io/docs/moonbitlang/workflow)
- [colmugx/mcp](https://mooncakes.io/docs/colmugx/mcp)
- [moonbitlang/parser](https://mooncakes.io/docs/moonbitlang/parser)
- [AegisRun](https://github.com/tuya-me/aegisrun)

