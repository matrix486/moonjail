# Architecture and trust boundary

`Policy` is pure MoonBit data. `compile` validates it, resolves syscall names
for the selected architecture, and emits a `SandboxPlan` containing a verified
classic BPF program, Landlock path rules, and resource limits. `explain` and
`disassemble` operate on that plan without executing a process.

The native runtime takes only a compiled plan and a command. The C shim forks,
sets `PR_SET_NO_NEW_PRIVS`, applies Landlock, resource limits, and seccomp, then
calls `execvp` in the child. A close-on-exec pipe carries setup failures to the
parent, so a setup error is distinguishable from the command's exit code.

The parent remains outside the sandbox and waits for the child. The current
result records exit or signal status and the probed Landlock ABI. The child
inherits its parent's environment and already-open standard streams. MoonJail
therefore expects the caller to control environment variables and inherited
file descriptors before invoking untrusted programs. It does not isolate
processes through namespaces or cgroups.

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
