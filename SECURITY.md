# Security policy

MoonJail is pre-1.0 security infrastructure. Treat every release as requiring
review for the exact kernel, architecture, and workload where it will run.

The runtime must fail closed when a policy marks Landlock or another kernel
capability as required. Silent fallback to an unrestricted child is a bug.
Path policies require Landlock ABI 3 or newer so file truncation remains
controllable. The seccomp compiler rejects x32 syscall numbers on x86_64.

Seccomp rules constrain syscall entry points, but denying `socket` alone does
not guarantee a process has no network access: an inherited socket descriptor
could still be used. The caller must close or control inherited descriptors
and sanitize the child's environment. The current runtime does not set up a
network namespace or isolate the parent process.

Please report vulnerabilities privately to the maintainer before public
disclosure. Do not include real secrets or private exploit payloads in an issue.
