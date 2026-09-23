# Security policy

MoonJail is pre-1.0 security infrastructure. Treat every release as requiring
review for the exact kernel, architecture, and workload where it will run.

The runtime must fail closed when a policy marks Landlock or another kernel
capability as required. Silent fallback to an unrestricted child is a bug.
Path policies require Landlock ABI 3 or newer so file truncation remains
controllable. The seccomp compiler rejects x32 syscall numbers on x86_64.
The runtime applies a 30-second wall-clock timeout by default, configurable
through `timeout_ms`; CPU limits alone do not stop a sleeping process.

Seccomp rules constrain syscall entry points, but denying `socket` alone does
not guarantee a process has no network access: standard input/output/error
could themselves be inherited sockets. MoonJail marks all other inherited
descriptors close-on-exec before applying the policy; if the kernel cannot do
this, setup fails at stage 7. The caller must control standard streams and
sanitize the child's environment. The current runtime does not set up a
network namespace or isolate the parent process. On timeout it kills the
child process group, but a descendant that deliberately leaves that group may
survive. Do not treat this as a complete hostile-process-tree containment
boundary.

Please report vulnerabilities privately to the maintainer before public
disclosure. Do not include real secrets or private exploit payloads in an issue.
