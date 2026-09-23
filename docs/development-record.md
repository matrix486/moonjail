# Development and review record

## Scope and decisions

MoonJail was selected after reviewing Mooncakes and GitHub alternatives; the
surveys are at the repository root. The implementation intentionally targets
Linux native commands rather than replacing existing Wasm sandboxes or process
managers. Pure policy and BPF compilation stay in MoonBit; a small C shim is
used where Linux syscalls and `fork`/`exec` require native FFI.

Key design decisions:

1. Compile a policy before execution. Validation and BPF disassembly can be
   inspected without launching an untrusted process.
2. Require Landlock ABI 3 for path policies so truncate control is not silently
   omitted on older kernels. Capability failure is an error, not an automatic
   unrestricted fallback.
3. Distinguish setup failure, child exit, signal, and wall-clock timeout in the
   result. The parent applies a monotonic deadline because `RLIMIT_CPU` does
   not stop a sleeping child.
4. Keep the demo self-contained: its socket probe is a subcommand of the
   MoonJail executable, while standard Linux `cat`/`head` demonstrate file
   access. No Python package or network service is needed for the demo.
5. Close inherited non-standard descriptors at `exec`: an integration scenario
   demonstrated that a preopened `/etc/passwd` descriptor bypassed a Landlock
   path restriction. The runtime now marks descriptors 3 and above
   close-on-exec and fails closed when the kernel cannot do so. Standard
   streams remain the caller's responsibility.

## AI assistance and human verification

AI assistance was used for ecosystem comparison, design alternatives, MoonBit
and C implementation drafts, tests, and documentation. The project owner is
responsible for reviewing policy semantics, generated syscall/BPF behavior,
security claims, licensing, and the final submission. The current changes were
checked with `moon fmt --check`, `moon check --target all`, native tests, and a
real Linux demo under the user-provided desktop-directory workspace. This is
not a formal security audit.
The descriptor regression was reproduced before the fix and passed after it;
both native C shims also passed GCC `-Wall -Wextra -Werror` syntax checks.

## Sources and originality

The implementation is original to this repository, not a copy or port of a
third-party library. Interface behavior was checked against primary Linux
documentation: [seccomp filters](https://docs.kernel.org/userspace-api/seccomp_filter.html),
[Landlock](https://docs.kernel.org/userspace-api/landlock.html), and
[`setrlimit(2)`](https://man7.org/linux/man-pages/man2/getrlimit.2.html), and
[`close_range(2)`](https://man7.org/linux/man-pages/man2/close_range.2.html).
The [MoonBit 2026 Hackathon page](https://moonbitlang.github.io/Hackathon2026/)
is the reference for the September submission checklist; formal organizer
notices remain authoritative if requirements change.

## Remaining release checks

- Verify aarch64 syscall preset and runtime on a physical/virtual Linux
  aarch64 host before advertising that target as supported.
- Obtain an independent security review before recommending hostile-code use.
- After publishing, link the public repository and Mooncakes package in the
  application, and retain genuine commits, Issues/PRs, and updates.
