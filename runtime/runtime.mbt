///|
/// How the child process terminated.
pub(all) enum RunStatus {
  Exited(Int)
  Signaled(Int)
  SetupFailed(stage~ : Int, errno~ : Int)
} derive(Debug, Eq, ToJson)

///|
/// Observable result from one sandboxed process.
pub(all) struct SandboxResult {
  status : RunStatus
  landlock_abi : Int
} derive(Debug, Eq, ToJson)

///|
/// Machine-readable result for command-line tools and integrations.
pub fn SandboxResult::to_json(self : SandboxResult) -> String {
  @json.to_json(self).stringify(indent=2)
}

///|
pub(all) suberror RuntimeError {
  UnsupportedPlatform
  ArchitectureMismatch(
    expected~ : @moonjail.Architecture,
    actual~ : @moonjail.Architecture
  )
  LandlockUnavailable
  InvalidCommand
  NativeFailure(Int)
} derive(Debug)

///|
pub extend RunStatus with Eq::{equal, not_equal}

///|
pub extend RunStatus with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend RunStatus with ToJson::{to_json}

///|
pub extend SandboxResult with Eq::{equal, not_equal}

///|
pub extend SandboxResult with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend RuntimeError with @moonbitlang/core/debug.Debug::{to_repr}

///|
extern "C" fn platform_ffi() -> Int = "moonjail_platform"

///|
extern "C" fn architecture_ffi() -> Int = "moonjail_architecture"

///|
extern "C" fn landlock_abi_ffi() -> Int = "moonjail_landlock_abi"

///|
#borrow(words, argv_blob, paths_blob)
extern "C" fn run_ffi(
  words : FixedArray[UInt],
  argv_blob : Bytes,
  paths_blob : Bytes,
  require_landlock : Int,
  cpu_seconds : Int,
  address_space_bytes : Int64,
  file_size_bytes : Int64,
  open_files : Int,
  processes : Int,
) -> Int64 = "moonjail_run"

///|
/// True only when the native process is running on Linux.
pub fn is_supported() -> Bool {
  platform_ffi() == 1
}

///|
/// Detect the architecture of the native runtime.
pub fn current_architecture() -> @moonjail.Architecture raise RuntimeError {
  match architecture_ffi() {
    1 => X86_64
    2 => AArch64
    _ => raise UnsupportedPlatform
  }
}

///|
/// Return the Landlock ABI version, 0 when unsupported, or a negative native
/// errno when probing failed for another reason.
pub fn landlock_abi() -> Int {
  landlock_abi_ffi()
}

///|
fn right_mask(right : @moonjail.AccessRight) -> UInt64 {
  match right {
    Execute => 1UL
    WriteFile => 2UL | 16384UL
    ReadFile => 4UL
    ReadDir => 8UL
    Remove => 16UL | 32UL
    MakeNode => 64UL | 128UL | 256UL | 512UL | 1024UL | 2048UL | 4096UL
    Refer => 8192UL
  }
}

///|
fn encode_paths(rules : Array[@moonjail.PathRule]) -> Bytes {
  let lines : Array[String] = []
  for rule in rules {
    let mut mask = 0UL
    for right in rule.rights {
      mask = mask | right_mask(right)
    }
    lines.push("\{mask}\t\{rule.path}")
  }
  @utf8.encode(lines.join("\n"))
}

///|
fn encode_argv(command : String, args : Array[String]) -> Bytes {
  let values = [command]
  values.append(args)
  @utf8.encode(values.join("\u{0}") + "\u{0}")
}

///|
fn optional_int(value : Int?) -> Int {
  match value {
    Some(value) => value
    None => -1
  }
}

///|
fn optional_int64(value : Int64?) -> Int64 {
  match value {
    Some(value) => value
    None => -1L
  }
}

///|
/// Run a command after applying Landlock, resource limits, and seccomp in the
/// child. Setup failures are reported separately from the command's exit code.
pub fn run(
  plan : @moonjail.SandboxPlan,
  command : String,
  args? : Array[String] = [],
) -> SandboxResult raise RuntimeError {
  if !is_supported() {
    raise UnsupportedPlatform
  }
  if command.is_empty() || command.contains("\u{0}") {
    raise InvalidCommand
  }
  for arg in args {
    if arg.contains("\u{0}") {
      raise InvalidCommand
    }
  }
  let actual = current_architecture()
  if actual != plan.architecture {
    raise ArchitectureMismatch(expected=plan.architecture, actual~)
  }
  let abi = landlock_abi()
  // ABI 3 is needed to deny truncation. Earlier ABIs would silently leave
  // that operation outside the handled rights set.
  if (plan.require_landlock || !plan.path_rules.is_empty()) && abi < 3 {
    raise LandlockUnavailable
  }
  let encoded = run_ffi(
    plan.seccomp.to_words(),
    encode_argv(command, args),
    encode_paths(plan.path_rules),
    if plan.require_landlock {
      1
    } else {
      0
    },
    optional_int(plan.limits.cpu_seconds),
    optional_int64(plan.limits.address_space_bytes),
    optional_int64(plan.limits.file_size_bytes),
    optional_int(plan.limits.open_files),
    optional_int(plan.limits.processes),
  )
  if encoded < 0L {
    raise NativeFailure(encoded.to_int())
  }
  let kind = (encoded / 1000000L).to_int()
  let detail = (encoded % 1000000L).to_int()
  let status = match kind {
    0 => Exited(detail)
    1 => Signaled(detail)
    2 => SetupFailed(stage=detail / 1000, errno=detail % 1000)
    _ => raise NativeFailure(encoded.to_int())
  }
  { status, landlock_abi: abi, }
}
