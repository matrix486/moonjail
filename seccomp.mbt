///|
let bpf_ld_w_abs : Int = 0x20

///|
let bpf_jmp_jeq_k : Int = 0x15

///|
let bpf_jmp_jge_k : Int = 0x35

///|
let bpf_ret_k : Int = 0x06

///|
let seccomp_data_nr_offset : UInt = 0U

///|
let seccomp_data_arch_offset : UInt = 4U

///|
fn action_value(action : SeccompAction) -> UInt {
  match action {
    KillProcess => 0x80000000U
    Trap => 0x00030000U
    Errno(errno) => 0x00050000U | (errno.reinterpret_as_uint() & 0x0000ffffU)
    Log => 0x7ffc0000U
    Allow => 0x7fff0000U
  }
}

///|
fn stmt(code : Int, k : UInt) -> BpfInstruction {
  { code, jt: 0, jf: 0, k, }
}

///|
fn jump(code : Int, k : UInt, jt : Int, jf : Int) -> BpfInstruction {
  { code, jt, jf, k, }
}

///|
/// Compile an unambiguous policy into a linear classic-BPF seccomp program.
pub fn compile(
  policy : Policy,
  architecture : Architecture,
) -> SandboxPlan raise CompileError {
  let diagnostics = validate_policy(policy)
  if !diagnostics.is_empty() {
    raise InvalidPolicy(diagnostics)
  }
  let instructions : Array[BpfInstruction] = [
    stmt(bpf_ld_w_abs, seccomp_data_arch_offset),
    jump(bpf_jmp_jeq_k, architecture.audit_value(), 1, 0),
    stmt(bpf_ret_k, action_value(KillProcess)),
    stmt(bpf_ld_w_abs, seccomp_data_nr_offset),
  ]
  // AUDIT_ARCH_X86_64 also identifies the x32 ABI. Its syscall numbers carry
  // bit 30, so reject that ABI before applying native x86_64 rules.
  if architecture == X86_64 {
    instructions.push(jump(bpf_jmp_jge_k, 0x40000000U, 0, 1))
    instructions.push(stmt(bpf_ret_k, action_value(KillProcess)))
  }
  for rule in policy.syscall_rules {
    let number = match syscall_number(architecture, rule.name) {
      Some(number) => number
      None => raise UnknownSyscall(architecture~, name=rule.name)
    }
    instructions.push(jump(bpf_jmp_jeq_k, number.reinterpret_as_uint(), 0, 1))
    instructions.push(stmt(bpf_ret_k, action_value(rule.action)))
  }
  instructions.push(stmt(bpf_ret_k, action_value(policy.default_action)))
  let program = { architecture, instructions, }
  verify_program(program)
  {
    name: policy.name,
    architecture,
    default_action: policy.default_action,
    syscall_rules: policy.syscall_rules,
    seccomp: program,
    path_rules: policy.path_rules,
    limits: policy.limits,
    require_landlock: policy.require_landlock,
  }
}

///|
/// Verify bounds and termination properties needed by the generated program.
pub fn verify_program(program : SeccompProgram) -> Unit raise CompileError {
  let len = program.instructions.length()
  if len == 0 {
    raise InvalidProgram("program is empty")
  }
  if len > 4096 {
    raise InvalidProgram("program exceeds Linux BPF_MAXINSNS")
  }
  for index, instruction in program.instructions {
    if instruction.code == bpf_jmp_jeq_k || instruction.code == bpf_jmp_jge_k {
      let true_target = index + 1 + instruction.jt
      let false_target = index + 1 + instruction.jf
      if instruction.jt < 0 ||
        instruction.jf < 0 ||
        true_target >= len ||
        false_target >= len {
        raise InvalidProgram("jump at instruction \{index} escapes program")
      }
    }
  }
  if program.instructions[len - 1].code != bpf_ret_k {
    raise InvalidProgram("program must end with RET")
  }
}

///|
/// Pack instructions as `[code, jt, jf, k, ...]` for the native runtime shim.
pub fn SeccompProgram::to_words(self : SeccompProgram) -> FixedArray[UInt] {
  let words : Array[UInt] = []
  for instruction in self.instructions {
    words.push(instruction.code.reinterpret_as_uint())
    words.push(instruction.jt.reinterpret_as_uint())
    words.push(instruction.jf.reinterpret_as_uint())
    words.push(instruction.k)
  }
  FixedArray::from_array(words)
}

///|
pub fn SeccompProgram::disassemble(self : SeccompProgram) -> String {
  let lines : Array[String] = []
  for index, instruction in self.instructions {
    let op = if instruction.code == bpf_ld_w_abs {
      "LD.W.ABS"
    } else if instruction.code == bpf_jmp_jeq_k {
      "JEQ.K"
    } else if instruction.code == bpf_jmp_jge_k {
      "JGE.K"
    } else if instruction.code == bpf_ret_k {
      "RET.K"
    } else {
      "UNKNOWN"
    }
    lines.push(
      "\{index}: \{op} k=\{instruction.k} jt=\{instruction.jt} jf=\{instruction.jf}",
    )
  }
  lines.join("\n")
}
