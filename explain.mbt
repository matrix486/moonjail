///|
fn action_name(action : SeccompAction) -> String {
  match action {
    Allow => "allow"
    Errno(errno) => "errno(\{errno})"
    Trap => "trap"
    Log => "log"
    KillProcess => "kill-process"
  }
}

///|
fn architecture_name(architecture : Architecture) -> String {
  match architecture {
    X86_64 => "x86_64"
    AArch64 => "aarch64"
  }
}

///|
/// Render a deterministic, human-readable explanation of a compiled plan.
pub fn SandboxPlan::explain(self : SandboxPlan) -> String {
  let out = StringBuilder()
  out.write_string("MoonJail plan: ")
  out.write_string(self.name)
  out.write_string("\narchitecture: ")
  out.write_string(architecture_name(self.architecture))
  out.write_string("\nseccomp instructions: ")
  out.write_string(self.seccomp.instructions.length().to_string())
  out.write_string("\ndefault action: ")
  out.write_string(action_name(self.default_action))
  out.write_string("\nsyscalls:")
  if self.syscall_rules.is_empty() {
    out.write_string(" none")
  } else {
    for rule in self.syscall_rules {
      out.write_string("\n  - \{rule.name}: \{action_name(rule.action)}")
    }
  }
  out.write_string("\nlandlock: ")
  out.write_string(
    if self.require_landlock || !self.path_rules.is_empty() {
      "required"
    } else {
      "off"
    },
  )
  out.write_string("\npaths:")
  if self.path_rules.is_empty() {
    out.write_string(" none")
  } else {
    for rule in self.path_rules {
      out.write_string("\n  - ")
      out.write_string(rule.path)
      out.write_string(" [")
      out.write_string(rule.rights.map(right => "\{Repr(right)}").join(", "))
      out.write_string("]")
    }
  }
  out.write_string("\nlimits:")
  let mut has_limit = false
  match self.limits.cpu_seconds {
    Some(value) => {
      out.write_string("\n  - cpu_seconds: \{value}")
      has_limit = true
    }
    None => ()
  }
  match self.limits.address_space_bytes {
    Some(value) => {
      out.write_string("\n  - address_space_bytes: \{value}")
      has_limit = true
    }
    None => ()
  }
  match self.limits.file_size_bytes {
    Some(value) => {
      out.write_string("\n  - file_size_bytes: \{value}")
      has_limit = true
    }
    None => ()
  }
  match self.limits.open_files {
    Some(value) => {
      out.write_string("\n  - open_files: \{value}")
      has_limit = true
    }
    None => ()
  }
  match self.limits.processes {
    Some(value) => {
      out.write_string("\n  - processes: \{value}")
      has_limit = true
    }
    None => ()
  }
  if !has_limit {
    out.write_string(" none")
  }
  out.write_string("\n")
  out.to_string()
}

///|
/// Summarize a policy before compilation.
pub fn Policy::summary(self : Policy) -> String {
  let lines : Array[String] = [
    "policy \{self.name}",
    "default: \{action_name(self.default_action)}",
    "syscall rules: \{self.syscall_rules.length()}",
    "path rules: \{self.path_rules.length()}",
  ]
  lines.join("\n")
}
