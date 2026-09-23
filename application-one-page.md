# MoonJail｜2026 年 9 月 MoonBit 黑客松项目说明（一页版）

**项目定位**：一个为 MoonBit 生态提供 Linux 原生进程最小权限隔离、策略解释与可审计执行能力的开源项目。

**真实问题**：MoonBit 的 Agent、CI 与插件宿主可以启动外部工具，但普通进程启动接口不会限制工具对文件、网络与内核调用的访问。MoonJail 让调用者先以 MoonBit builder 或 JSON 定义策略，再编译和执行受限子进程。

**生态增量**：与要求工具运行在 Wasm 中的 AegisRun 不同，MoonJail 面向现成 Linux ELF/脚本；与通用进程管理包不同，它提供 seccomp syscall 筛选、Landlock 文件权限、`no_new_privs`、rlimit、墙钟超时和可解释的编译结果。策略、校验、BPF 编译与 CLI 由 MoonBit 实现；C 只负责必要的原生内核调用。

**当前交付**：版本化 JSON 策略、MoonBit builder、x86_64/aarch64 syscall 元数据、classic-BPF 编译与静态验证、Landlock 路径规则、Linux 子进程运行器、结构化执行状态、跨平台策略检查、CLI 与演示。当前已在 Linux x86_64 / Landlock ABI 8 上实测；aarch64 运行与 preset 尚待硬件验证。仓库包含 24 项原生测试及 Linux/Windows CI 配置。

**三分钟演示**（Linux，仓库根目录，需 MoonBit 工具链和 C 编译器）：

```sh
moon run cmd/moonjail -- capabilities
moon run cmd/moonjail -- explain
moon run cmd/moonjail -- demo
```

演示先显示策略和内核能力，再由项目自身的 socket 探针触发 seccomp 拒绝；一个声明过的文件可以读取，`/etc/passwd` 不可读取；补充授权后，同一读取命令成功。`README.mbt.md` 给出完整复现和测试命令。

**质量与边界**：内核能力不足时路径策略拒绝运行，不静默降级。测试覆盖网络、读/写/执行权限、资源限制、子进程超时、策略序列化和 BPF；另有 Agent 工具集成场景验证继承描述符不能绕过 Landlock。MoonJail 在执行前关闭非标准描述符，但不是容器；调用方仍需控制标准流与环境变量，进程组之外的后代也不在当前隔离范围内。详见 `SECURITY.md`。

**维护路线**：先验证 Linux aarch64 和更多内核版本，再做 Agent/CI 适配与更严格的进程树隔离。项目采用 Apache-2.0 许可；架构、源码参考及 AI 辅助开发过程见 `docs/`。

本页对应 [2026 年 9 月官方黑客松](https://moonbitlang.github.io/Hackathon2026/) 的“一页项目说明”要求。公开仓库、报名信息、赛事群与 Mooncakes 发布仍需参赛者完成；本文件不代替官方申报。
