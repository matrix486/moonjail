///|
/// CPU architecture understood by the seccomp compiler.
pub(all) enum Architecture {
  X86_64
  AArch64
} derive(Debug, Eq)

///|
/// Result returned by a matching seccomp rule.
pub(all) enum SeccompAction {
  Allow
  Errno(Int)
  Trap
  Log
  KillProcess
} derive(Debug, Eq)

///|
/// One named syscall rule. The architecture-specific number is resolved when
/// the policy is compiled.
pub(all) struct SyscallRule {
  name : String
  action : SeccompAction
} derive(Debug, Eq)

///|
/// Filesystem access rights enforced through Landlock on supported kernels.
pub(all) enum AccessRight {
  ReadFile
  ReadDir
  WriteFile
  Remove
  MakeNode
  Execute
  Refer
} derive(Debug, Eq)

///|
/// A path and the rights granted below it.
pub(all) struct PathRule {
  path : String
  rights : Array[AccessRight]
} derive(Debug, Eq)

///|
/// Resource limits applied before exec.
pub(all) struct ResourceLimits {
  cpu_seconds : Int?
  address_space_bytes : Int64?
  file_size_bytes : Int64?
  open_files : Int?
  processes : Int?
} derive(Debug, Eq)

///|
/// A complete, declarative sandbox policy.
pub(all) struct Policy {
  name : String
  default_action : SeccompAction
  syscall_rules : Array[SyscallRule]
  path_rules : Array[PathRule]
  limits : ResourceLimits
  require_landlock : Bool
} derive(Debug, Eq)

///|
/// Built-in starting points. Profiles remain ordinary policies and can be
/// extended with the builder methods.
pub(all) enum Profile {
  Minimal
  ConsoleTool
  BuildStep
} derive(Debug, Eq)

///|
/// One classic-BPF instruction as consumed by Linux seccomp.
pub(all) struct BpfInstruction {
  code : Int
  jt : Int
  jf : Int
  k : UInt
} derive(Debug, Eq)

///|
/// A verified seccomp program plus the architecture it targets.
pub(all) struct SeccompProgram {
  architecture : Architecture
  instructions : Array[BpfInstruction]
} derive(Debug, Eq)

///|
/// Pure-data output of policy compilation. It can be inspected or serialized
/// without invoking any platform API.
pub(all) struct SandboxPlan {
  name : String
  architecture : Architecture
  default_action : SeccompAction
  syscall_rules : Array[SyscallRule]
  seccomp : SeccompProgram
  path_rules : Array[PathRule]
  limits : ResourceLimits
  require_landlock : Bool
} derive(Debug, Eq)

///|
/// Policy or compiler diagnostics carry a stable code for tools and a human
/// readable message for CLI users.
pub(all) struct Diagnostic {
  code : String
  message : String
} derive(Debug, Eq)

///|
pub(all) suberror CompileError {
  InvalidPolicy(Array[Diagnostic])
  UnknownSyscall(architecture~ : Architecture, name~ : String)
  InvalidProgram(String)
} derive(Debug)

///|
pub extend Architecture with Eq::{equal, not_equal}

///|
pub extend Architecture with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SeccompAction with Eq::{equal, not_equal}

///|
pub extend SeccompAction with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SyscallRule with Eq::{equal, not_equal}

///|
pub extend SyscallRule with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend AccessRight with Eq::{equal, not_equal}

///|
pub extend AccessRight with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend PathRule with Eq::{equal, not_equal}

///|
pub extend PathRule with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend ResourceLimits with Eq::{equal, not_equal}

///|
pub extend ResourceLimits with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Policy with Eq::{equal, not_equal}

///|
pub extend Policy with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Profile with Eq::{equal, not_equal}

///|
pub extend Profile with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend BpfInstruction with Eq::{equal, not_equal}

///|
pub extend BpfInstruction with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SeccompProgram with Eq::{equal, not_equal}

///|
pub extend SeccompProgram with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SandboxPlan with Eq::{equal, not_equal}

///|
pub extend SandboxPlan with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Diagnostic with Eq::{equal, not_equal}

///|
pub extend Diagnostic with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend CompileError with @moonbitlang/core/debug.Debug::{to_repr}
