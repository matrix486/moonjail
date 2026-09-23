///|
test "runtime capability probe is stable" {
  let supported = @runtime.is_supported()
  if supported {
    assert_true(@runtime.landlock_abi() >= 0)
  } else {
    assert_eq(@runtime.landlock_abi(), 0)
  }
}

///|
test "non-linux run fails before native execution" {
  if !@runtime.is_supported() {
    let plan = @moonjail.compile(
      @moonjail.Policy::from_profile(Minimal).with_landlock_required(false),
      X86_64,
    )
    try @runtime.run(plan, "ignored") catch {
      UnsupportedPlatform => ()
      _ => fail("expected UnsupportedPlatform")
    } noraise {
      _ => fail("expected run to fail")
    }
  }
}

///|
test "linux seccomp denies socket creation" {
  if @runtime.is_supported() {
    let architecture = @runtime.current_architecture()
    let policy = @moonjail.Policy::allow_by_default(name="deny-network")
      .deny_syscall("socket", errno=13)
      .with_landlock_required(false)
    let plan = @moonjail.compile(policy, architecture)
    let result = @runtime.run(plan, "/usr/bin/python3", args=[
      "-c", "import socket; socket.socket()",
    ])
    match result.status {
      Exited(code) => assert_true(code != 0)
      _ => fail("python should report a denied socket as a non-zero exit")
    }
  }
}

///|
test "linux reports exec setup failure separately" {
  if @runtime.is_supported() {
    let plan = @moonjail.compile(
      @moonjail.Policy::allow_by_default().with_landlock_required(false),
      @runtime.current_architecture(),
    )
    let result = @runtime.run(plan, "/moonjail-command-that-does-not-exist")
    match result.status {
      SetupFailed(stage~, errno~) => {
        assert_eq(stage, 5)
        assert_eq(errno, 2)
      }
      _ => fail("missing command must be a setup failure")
    }
  }
}

///|
test "linux enforces CPU resource limit" {
  if @runtime.is_supported() {
    let plan = @moonjail.compile(
      @moonjail.Policy::allow_by_default()
      .with_landlock_required(false)
      .limit_cpu(1),
      @runtime.current_architecture(),
    )
    let result = @runtime.run(plan, "/usr/bin/python3", args=[
      "-c", "while True: pass",
    ])
    match result.status {
      Signaled(_) => ()
      _ => fail("CPU-bound child must hit RLIMIT_CPU")
    }
  }
}

///|
fn landlock_test_policy() -> @moonjail.Policy {
  @moonjail.Policy::allow_by_default(name="landlock-read")
  .allow_path("/usr", [ReadFile, ReadDir, Execute])
  .allow_path("/lib", [ReadFile, ReadDir, Execute])
  .allow_path("/lib64", [ReadFile, ReadDir, Execute])
  .allow_path("/etc/ld.so.cache", [ReadFile])
  .allow_path("./runtime/fixtures", [ReadFile, ReadDir])
}

///|
test "linux deny-by-default console profile runs a declared reader" {
  if @runtime.is_supported() &&
    @runtime.landlock_abi() >= 3 &&
    @runtime.current_architecture() == X86_64 {
    let base = landlock_test_policy()
    let strict = @moonjail.Policy::from_profile(ConsoleTool)
    for rule in base.path_rules {
      ignore(strict.allow_path(rule.path, rule.rights))
    }
    let plan = @moonjail.compile(strict, X86_64)
    let result = @runtime.run(plan, "/usr/bin/cat", args=[
      "./runtime/fixtures/allowed.txt",
    ])
    assert_eq(result.status, Exited(0))
  }
}

///|
test "linux landlock allows declared path and denies undeclared path" {
  if @runtime.is_supported() && @runtime.landlock_abi() > 0 {
    let plan = @moonjail.compile(
      landlock_test_policy(),
      @runtime.current_architecture(),
    )
    let allowed = @runtime.run(plan, "/usr/bin/cat", args=[
      "./runtime/fixtures/allowed.txt",
    ])
    assert_eq(allowed.status, Exited(0))
    let denied = @runtime.run(plan, "/usr/bin/cat", args=["/etc/passwd"])
    match denied.status {
      Exited(code) => assert_true(code != 0)
      _ => fail("cat should receive a filesystem denial")
    }
  }
}
