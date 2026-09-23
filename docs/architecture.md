# Architecture and trust boundary

`Policy` is pure MoonBit data. `compile` validates it, resolves syscall names
for the selected architecture, and emits a `SandboxPlan` containing a verified
classic BPF program, Landlock path rules, and resource limits. `explain` and
`disassemble` operate on that plan without executing a process.

The native runtime takes only a compiled plan and a command. The C shim forks,
sets `PR_SET_NO_NEW_PRIVS`, applies Landlock, resource limits, and seccomp, then
calls `execvp` in the child. A close-on-exec pipe carries setup failures to the
parent, so a setup error is distinguishable from the command's exit code.
Before restrictions are applied, `close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)`
ensures inherited non-standard file descriptors cannot bypass Landlock after
`execvp`; the setup pipe remains usable until that point. This requires Linux
5.11 or newer and fails closed at setup stage 7 if unavailable.

The parent remains outside the sandbox and waits for the child with a
monotonic wall-clock deadline (30 seconds by default). On timeout it sends
SIGKILL to the child's process group and reaps the direct child. The result
records exit, signal, timeout, or setup-failure status and the probed
Landlock ABI. The child inherits its parent's environment and already-open
standard streams. MoonJail therefore expects the caller to control environment
variables and standard streams before invoking untrusted programs. It does not isolate
processes through namespaces or cgroups.
It is not a hardened process-tree supervisor: a descendant that creates a
new session can escape the child's process group. Callers handling hostile
forking workloads need a cgroup or namespace boundary in addition.

## Policy document v1

`Policy::to_json` and `Policy::from_json` round-trip the complete policy. The
document has a mandatory `version: 1`; unsupported versions fail during
parsing. A parsed policy must still pass `compile` before execution. Actions
use `{ "kind": "allow" }`, `{ "kind": "errno", "errno": 13 }`, `trap`,
`log`, or `kill_process`. Path rights are `read_file`, `read_dir`, `write_file`,
`remove`, `make_node`, `execute`, and `refer`.

## Kernel compatibility

The runtime requires Linux x86_64 or aarch64 for execution. Landlock policies
require ABI 3 or newer because ABI 1 and 2 cannot restrict truncation. A
policy without paths and with `require_landlock: false` does not apply
Landlock. The runtime rejects architecture mismatches before forking.

`ConsoleTool` and `BuildStep` are currently tested on x86_64. The minimal
aarch64 syscall mapping supports explicit policies; preset conformance on an
aarch64 Linux host remains a pre-release task.

On x86_64, the audit architecture identifier is shared with the x32 ABI.
The compiler rejects syscall numbers with the x32 bit before evaluating policy
rules. See the [seccomp manual](https://man7.org/linux/man-pages/man2/seccomp.2.html).

## Design sources

- [Linux kernel seccomp filter guide](https://docs.kernel.org/userspace-api/seccomp_filter.html): syscall filtering and `no_new_privs` requirements; seccomp alone is not a complete sandbox.
- [Linux kernel Landlock guide](https://docs.kernel.org/userspace-api/landlock.html): handled filesystem rights, ABI compatibility, and inherited restrictions.
- [Linux `setrlimit(2)` manual](https://man7.org/linux/man-pages/man2/getrlimit.2.html): resource-limit semantics.
- [Linux `close_range(2)` manual](https://man7.org/linux/man-pages/man2/close_range.2.html): close-on-exec descriptor isolation.
