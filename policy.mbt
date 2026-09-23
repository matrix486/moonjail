///|
fn empty_limits() -> ResourceLimits {
  {
    cpu_seconds: None,
    address_space_bytes: None,
    file_size_bytes: None,
    open_files: None,
    processes: None,
  }
}

///|
/// Start a deny-by-default policy. Unknown syscalls fail with EPERM.
pub fn Policy::deny_by_default(name? : String = "custom") -> Policy {
  {
    name,
    default_action: Errno(1),
    syscall_rules: [],
    path_rules: [],
    limits: empty_limits(),
    require_landlock: true,
  }
}

///|
/// Start a permissive policy for audit and migration work.
pub fn Policy::allow_by_default(name? : String = "audit") -> Policy {
  {
    name,
    default_action: Allow,
    syscall_rules: [],
    path_rules: [],
    limits: empty_limits(),
    require_landlock: false,
  }
}

///|
/// Add or override no rules: duplicate syscall names are rejected at compile
/// time so the resulting policy is unambiguous.
pub fn Policy::on_syscall(
  self : Policy,
  name : String,
  action : SeccompAction,
) -> Policy {
  self.syscall_rules.push({ name, action, })
  self
}

///|
pub fn Policy::allow_syscall(self : Policy, name : String) -> Policy {
  self.on_syscall(name, Allow)
}

///|
pub fn Policy::deny_syscall(
  self : Policy,
  name : String,
  errno? : Int = 1,
) -> Policy {
  self.on_syscall(name, Errno(errno))
}

///|
pub fn Policy::allow_path(
  self : Policy,
  path : String,
  rights : Array[AccessRight],
) -> Policy {
  self.path_rules.push({ path, rights, })
  self
}

///|
pub fn Policy::allow_read(self : Policy, path : String) -> Policy {
  self.allow_path(path, [ReadFile, ReadDir])
}

///|
pub fn Policy::allow_write(self : Policy, path : String) -> Policy {
  self.allow_path(path, [ReadFile, ReadDir, WriteFile, Remove, MakeNode, Refer])
}

///|
pub fn Policy::with_landlock_required(self : Policy, required : Bool) -> Policy {
  {
    name: self.name,
    default_action: self.default_action,
    syscall_rules: self.syscall_rules,
    path_rules: self.path_rules,
    limits: self.limits,
    require_landlock: required,
  }
}

///|
pub fn Policy::limit_cpu(self : Policy, seconds : Int) -> Policy {
  let limits = { ..self.limits, cpu_seconds: Some(seconds), }
  { ..self, limits, }
}

///|
pub fn Policy::limit_memory(self : Policy, bytes : Int64) -> Policy {
  let limits = { ..self.limits, address_space_bytes: Some(bytes), }
  { ..self, limits, }
}

///|
pub fn Policy::limit_file_size(self : Policy, bytes : Int64) -> Policy {
  let limits = { ..self.limits, file_size_bytes: Some(bytes), }
  { ..self, limits, }
}

///|
pub fn Policy::limit_open_files(self : Policy, count : Int) -> Policy {
  let limits = { ..self.limits, open_files: Some(count), }
  { ..self, limits, }
}

///|
pub fn Policy::limit_processes(self : Policy, count : Int) -> Policy {
  let limits = { ..self.limits, processes: Some(count), }
  { ..self, limits, }
}

///|
fn allow_many(policy : Policy, names : Array[String]) -> Policy {
  for name in names {
    ignore(policy.allow_syscall(name))
  }
  policy
}

///|
/// Create one of the maintained baseline profiles.
pub fn Policy::from_profile(profile : Profile) -> Policy {
  match profile {
    Minimal => {
      let policy = Policy::deny_by_default(name="minimal")
      allow_many(policy, ["exit", "exit_group", "rt_sigreturn"])
    }
    ConsoleTool => {
      let policy = Policy::deny_by_default(name="console-tool")
      allow_many(policy, [
        "read", "write", "close", "fstat", "newfstatat", "lseek", "mmap", "mprotect",
        "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl",
        "fcntl", "pread64", "access", "openat", "readlink", "arch_prctl", "set_tid_address",
        "set_robust_list", "prlimit64", "getrandom", "rseq", "futex", "clock_gettime",
        "statx", "splice", "sigaltstack", "statfs", "poll", "prctl", "sched_getaffinity",
        "getpid", "gettid", "execve", "exit", "exit_group",
      ])
    }
    BuildStep => {
      let base = Policy::from_profile(ConsoleTool)
      allow_many({ ..base, name: "build-step", }, [
        "clone", "clone3", "wait4", "pipe2", "dup", "dup2", "dup3", "getcwd", "chdir",
        "mkdirat", "unlinkat", "renameat2",
      ])
    }
  }
}
