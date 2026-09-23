///|
fn positive_limit(
  diagnostics : Array[Diagnostic],
  code : String,
  label : String,
  value : Int?,
) -> Unit {
  match value {
    Some(n) if n <= 0 =>
      diagnostics.push({ code, message: "\{label} must be greater than zero", })
    _ => ()
  }
}

///|
/// Validate policy-level invariants before architecture-specific compilation.
pub fn validate_policy(policy : Policy) -> Array[Diagnostic] {
  let diagnostics : Array[Diagnostic] = []
  let names : Map[String, Bool] = Map([])
  for rule in policy.syscall_rules {
    if rule.name.trim().is_empty() {
      diagnostics.push({
        code: "MJ001",
        message: "syscall name must not be empty",
      })
    } else if names.contains(rule.name) {
      diagnostics.push({
        code: "MJ002",
        message: "duplicate syscall rule: \{rule.name}",
      })
    } else {
      names[rule.name] = true
    }
    match rule.action {
      Errno(value) if value <= 0 || value > 4095 =>
        diagnostics.push({
          code: "MJ003",
          message: "errno for \{rule.name} must be in 1..4095",
        })
      _ => ()
    }
  }
  for rule in policy.path_rules {
    if rule.path.trim().is_empty() {
      diagnostics.push({ code: "MJ004", message: "path must not be empty", })
    }
    if rule.path.contains("\u{0}") ||
      rule.path.contains("\n") ||
      rule.path.contains("\t") {
      diagnostics.push({
        code: "MJ011",
        message: "path must not contain NUL, newline, or tab",
      })
    }
    if rule.rights.is_empty() {
      diagnostics.push({
        code: "MJ005",
        message: "path rule for \{rule.path} grants no rights",
      })
    }
  }
  positive_limit(diagnostics, "MJ006", "cpu_seconds", policy.limits.cpu_seconds)
  positive_limit(diagnostics, "MJ007", "open_files", policy.limits.open_files)
  positive_limit(diagnostics, "MJ008", "processes", policy.limits.processes)
  match policy.limits.address_space_bytes {
    Some(n) if n <= 0L =>
      diagnostics.push({
        code: "MJ009",
        message: "address_space_bytes must be greater than zero",
      })
    _ => ()
  }
  match policy.limits.file_size_bytes {
    Some(n) if n <= 0L =>
      diagnostics.push({
        code: "MJ010",
        message: "file_size_bytes must be greater than zero",
      })
    _ => ()
  }
  diagnostics
}
