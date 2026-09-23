# MoonJail

MoonJail compiles a MoonBit policy into a Linux seccomp filter, Landlock file
rules, and resource limits, then runs a child process under those limits. The
policy compiler and explanation work across MoonBit targets; process execution
requires Linux.

The v0.1 prototype runs on Linux x86_64 and has been exercised on a host with
Landlock ABI 8. Native execution on aarch64 and the built-in presets there
still need hardware validation before a release.
The latest local verification used MoonBit `0.1.20260920`, Ubuntu x86_64
kernel `7.0.0-31-generic`, and GCC `15.2.0`; portable checks also passed on
Windows with MoonBit `0.1.20260915`.

## Try the three-minute demo

Install the current MoonBit toolchain and a C compiler. The demo needs only
the project binary and standard Linux `cat`/`head` utilities; it does not
require Python or a network service. From the repository root on Linux:

```sh
moon run cmd/moonjail -- capabilities
moon run cmd/moonjail -- explain
moon run cmd/moonjail -- demo
moon run cmd/moonjail -- check examples/deny-socket.json
moon run cmd/moonjail -- explain-profile examples/deny-socket.json
```

`demo` shows a network socket rejected by seccomp, a declared file read, an
undeclared `/etc/passwd` read rejected by Landlock, and the same read succeeding
after its policy grants access. It prints structured JSON statuses. The
successful retry reads zero bytes so it does not display the file contents.
The demo uses MoonJail's own `probe-socket` subcommand as the test child. To
test another command, use `run-deny-socket <command> [args...]`.

## MoonBit API

```mbt check
///|
test "compile a console tool policy" {
  let policy = @moonjail.Policy::from_profile(ConsoleTool)
    .allow_read("./workspace")
    .allow_write("./workspace/out")
    .limit_cpu(2)
    .limit_open_files(32)
  let plan = @moonjail.compile(policy, X86_64)
  assert_true(plan.seccomp.instructions.length() > 0)
}
```

The runtime API is `@runtime.run(plan, command, args=[...], timeout_ms=30000)`.
It reports `Exited(code)`, `Signaled(signal)`, `TimedOut`, or
`SetupFailed(stage, errno)` and can
serialize a result to JSON. `Policy::to_json` and `Policy::from_json` provide a
versioned policy document; `compile` checks it before execution. The
[architecture guide](docs/architecture.md) describes the schema and process
boundary.

## Build and test

```sh
moon fmt --check
moon check --target all --warn-list +unnecessary_annotation
moon test --target native
moon build --target native
```

Linux integration tests use Bash and standard coreutils to exercise seccomp
and Landlock. On Windows, runtime
tests confirm the unsupported-platform result while the portable compiler
tests still run.

The CLI returns 0 on success, 2 for usage errors, 3 for invalid input or
runtime setup errors, and 10 when a sandboxed command exits unsuccessfully,
is signaled, times out, or cannot be executed. Diagnostics for input/setup
errors go to stderr; `run` still prints its structured result to stdout.

The one-page [application summary](application-one-page.md) and
[development record](docs/development-record.md) are prepared for review.

MoonJail limits a non-root child; it is not a container runtime. The caller
must control inherited environment variables and file descriptors. See
[SECURITY.md](SECURITY.md) for the threat model and
[CONTRIBUTING.md](CONTRIBUTING.md) for development guidance.

The [Mooncakes survey](mooncake-ecosystem-analysis.md), [GitHub survey](github-ecosystem-analysis.md),
and [hackathon proposal](project-proposal.md) document the project choice.

Licensed under Apache-2.0.
