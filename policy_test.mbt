///|
test "console profile compiles for x86_64" {
  let plan = @moonjail.compile(
    @moonjail.Policy::from_profile(ConsoleTool),
    X86_64,
  )
  assert_true(plan.seccomp.instructions.length() > 20)
  assert_eq(plan.seccomp.instructions[0].k, 4U)
  assert_eq(plan.seccomp.instructions[1].k, 0xc000003eU)
}

///|
test "architecture mismatch is a kill path" {
  let plan = @moonjail.compile(
    @moonjail.Policy::deny_by_default().allow_syscall("write"),
    AArch64,
  )
  assert_eq(plan.seccomp.instructions[1].jt, 1)
  assert_eq(plan.seccomp.instructions[1].jf, 0)
  assert_eq(plan.seccomp.instructions[2].k, 0x80000000U)
}

///|
test "x86_64 rejects x32 syscall numbers before policy rules" {
  let plan = @moonjail.compile(
    @moonjail.Policy::allow_by_default().deny_syscall("socket"),
    X86_64,
  )
  assert_eq(plan.seccomp.instructions[4].code, 0x35)
  assert_eq(plan.seccomp.instructions[4].k, 0x40000000U)
  assert_eq(plan.seccomp.instructions[5].k, 0x80000000U)
}

///|
test "duplicate syscall rule is rejected" {
  let policy = @moonjail.Policy::deny_by_default()
    .allow_syscall("read")
    .deny_syscall("read")
  try @moonjail.compile(policy, X86_64) catch {
    InvalidPolicy(diagnostics) => {
      assert_eq(diagnostics.length(), 1)
      assert_eq(diagnostics[0].code, "MJ002")
    }
    _ => fail("unexpected compile error")
  } noraise {
    _ => fail("expected duplicate syscall rule to fail")
  }
}

///|
test "unknown syscall is architecture-specific" {
  let policy = @moonjail.Policy::deny_by_default().allow_syscall(
    "not_a_syscall",
  )
  try @moonjail.compile(policy, X86_64) catch {
    UnknownSyscall(name~, ..) => assert_eq(name, "not_a_syscall")
    _ => fail("unexpected compile error")
  } noraise {
    _ => fail("expected unknown syscall to fail")
  }
}

///|
test "verifier rejects oversized BPF programs" {
  let instructions : Array[@moonjail.BpfInstruction] = []
  for _ in 0..<4097 {
    instructions.push({ code: 6, jt: 0, jf: 0, k: 0x7fff0000U, })
  }
  let program : @moonjail.SeccompProgram = {
    architecture: X86_64,
    instructions,
  }
  try @moonjail.verify_program(program) catch {
    InvalidProgram(_) => ()
    _ => fail("expected InvalidProgram")
  } noraise {
    _ => fail("expected oversized program to fail")
  }
}

///|
test "path delimiters cannot alter serialized Landlock rules" {
  let policy = @moonjail.Policy::deny_by_default().allow_read("./safe\n0\t/etc")
  let diagnostics = @moonjail.validate_policy(policy)
  assert_eq(diagnostics.length(), 1)
  assert_eq(diagnostics[0].code, "MJ011")
}

///|
test "duplicate path rules cannot silently combine permissions" {
  let policy = @moonjail.Policy::deny_by_default()
    .allow_read("./workspace")
    .allow_write("./workspace")
  try @moonjail.compile(policy, X86_64) catch {
    InvalidPolicy(diagnostics) => {
      assert_eq(diagnostics.length(), 1)
      assert_eq(diagnostics[0].code, "MJ012")
      assert_true(diagnostics[0].message.contains("./workspace"))
    }
    _ => fail("unexpected compile error")
  } noraise {
    _ => fail("expected duplicate path rule to fail")
  }
}

///|
test "nested path rules remain valid" {
  let policy = @moonjail.Policy::deny_by_default()
    .allow_read("./workspace")
    .allow_write("./workspace/out")
  assert_true(@moonjail.validate_policy(policy).is_empty())
}

///|
test "explanation names syscall decisions and resource limits" {
  let policy = @moonjail.Policy::deny_by_default()
    .allow_syscall("read")
    .limit_cpu(2)
  let explanation = @moonjail.compile(policy, X86_64).explain()
  assert_true(explanation.contains("read: allow"))
  assert_true(explanation.contains("cpu_seconds: 2"))
  assert_true(explanation.contains("default action: errno(1)"))
}

///|
test "builder records paths and limits" {
  let policy = @moonjail.Policy::from_profile(ConsoleTool)
    .allow_read("./input")
    .allow_write("./output")
    .limit_cpu(2)
    .limit_memory(134217728L)
    .limit_open_files(32)
  assert_eq(policy.path_rules.length(), 2)
  assert_eq(policy.limits.cpu_seconds, Some(2))
  assert_eq(policy.limits.address_space_bytes, Some(134217728L))
  assert_eq(policy.limits.open_files, Some(32))
}
