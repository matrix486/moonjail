///|
fn usage() -> Unit {
  println(
    (
      #|MoonJail — Linux least-privilege sandbox
      #|
      #|Usage:
      #|  moonjail capabilities
      #|  moonjail explain
      #|  moonjail check <policy.json>
      #|  moonjail explain-profile <policy.json>
      #|  moonjail run <policy.json> <command> [args...]
      #|  moonjail run-deny-socket <command> [args...]
      #|  moonjail demo
      #|
    ),
  )
}

///|
fn command_args(args : Array[String], start : Int) -> Array[String] {
  let result : Array[String] = []
  for index in start..<args.length() {
    result.push(args[index])
  }
  result
}

///|
fn selected_architecture() -> @sandbox.Architecture raise {
  if @runtime.is_supported() {
    @runtime.current_architecture()
  } else {
    X86_64
  }
}

///|
fn load_plan(path : String) -> @sandbox.SandboxPlan raise {
  let content = @fs.read_file_to_string(path)
  let policy = @sandbox.Policy::from_json(content)
  @sandbox.compile(policy, selected_architecture())
}

///|
fn profile_command(args : Array[String], mode : String) -> Int raise {
  if args.length() < 3 || (mode == "run" && args.length() < 4) {
    usage()
    return 2
  }
  let plan = load_plan(args[2])
  match mode {
    "check" => {
      println("valid policy: \{plan.name}")
      0
    }
    "explain-profile" => {
      println(plan.explain())
      0
    }
    "run" => {
      let result = @runtime.run(plan, args[3], args=command_args(args, 4))
      println(result.to_json())
      match result.status {
        Exited(0) => 0
        _ => 10
      }
    }
    _ => 2
  }
}

///|
fn show_capabilities() -> Unit raise {
  println(
    "platform: \{if @runtime.is_supported() { "linux" } else { "unsupported" }}",
  )
  if @runtime.is_supported() {
    println("architecture: \{Repr(@runtime.current_architecture())}")
    println("landlock ABI: \{@runtime.landlock_abi()}")
    println("seccomp: available")
  }
}

///|
fn show_plan(show_program : Bool) -> Unit raise {
  let policy = demo_file_policy()
  let architecture = if @runtime.is_supported() {
    @runtime.current_architecture()
  } else {
    X86_64
  }
  let plan = @sandbox.compile(policy, architecture)
  if show_program {
    println(plan.explain())
    println("seccomp program:")
    println(plan.seccomp.disassemble())
  } else {
    println(policy.summary())
    println("landlock paths: \{plan.path_rules.length()}")
    let cpu = match plan.limits.cpu_seconds {
      Some(value) => "\{value}s"
      None => "none"
    }
    let open_files = match plan.limits.open_files {
      Some(value) => value.to_string()
      None => "none"
    }
    println("limits: CPU \{cpu}, open files \{open_files}")
  }
}

///|
fn run_deny_socket(args : Array[String]) -> Int raise {
  if args.length() < 3 {
    usage()
    return 2
  }
  let architecture = @runtime.current_architecture()
  let policy = @sandbox.Policy::allow_by_default(name="deny-socket")
    .deny_syscall("socket", errno=13)
    .with_landlock_required(false)
  let plan = @sandbox.compile(policy, architecture)
  let result = @runtime.run(plan, args[2], args=command_args(args, 3))
  println(result.to_json())
  match result.status {
    Exited(0) => 0
    _ => 10
  }
}

///|
fn demo_file_policy() -> @sandbox.Policy {
  @sandbox.Policy::from_profile(ConsoleTool)
  .allow_path("/usr", [ReadFile, ReadDir, Execute])
  .allow_path("/lib", [ReadFile, ReadDir, Execute])
  .allow_path("/lib64", [ReadFile, ReadDir, Execute])
  .allow_path("/etc/ld.so.cache", [ReadFile])
  .allow_path("./runtime/fixtures", [ReadFile, ReadDir])
  .limit_cpu(2)
  .limit_open_files(32)
}

///|
suberror DemoFailure {
  DemoFailure(String)
} derive(Debug)

///|
fn demo() -> Unit raise {
  if !@runtime.is_supported() {
    raise DemoFailure("the live demo requires Linux")
  }
  if @runtime.landlock_abi() < 3 {
    raise DemoFailure("the live demo requires Landlock ABI 3 or newer")
  }
  println("== kernel capabilities ==")
  show_capabilities()
  println("\n== policy explanation ==")
  show_plan(false)
  println("\n== deny socket creation ==")
  let architecture = @runtime.current_architecture()
  let policy = @sandbox.Policy::allow_by_default(name="demo-deny-socket")
    .deny_syscall("socket", errno=13)
    .with_landlock_required(false)
  let plan = @sandbox.compile(policy, architecture)
  let result = @runtime.run(plan, @env.args()[0], args=["probe-socket"])
  println("socket attempt: \{result.to_json()}")
  if result.status != Exited(1) {
    raise DemoFailure("socket probe did not report a denied socket")
  }
  println("\n== Landlock file policy ==")
  let restricted = @sandbox.compile(demo_file_policy(), architecture)
  let allowed = @runtime.run(restricted, "/usr/bin/cat", args=[
    "./runtime/fixtures/allowed.txt",
  ])
  println("declared file: \{allowed.to_json()}")
  if allowed.status != Exited(0) {
    raise DemoFailure("declared file read failed")
  }
  let denied = @runtime.run(restricted, "/usr/bin/head", args=[
    "-c", "0", "/etc/passwd",
  ])
  println("undeclared file: \{denied.to_json()}")
  match denied.status {
    Exited(code) if code != 0 => ()
    _ => raise DemoFailure("undeclared file was not denied")
  }
  let relaxed = @sandbox.compile(
    demo_file_policy().allow_path("/etc/passwd", [ReadFile]),
    architecture,
  )
  let retried = @runtime.run(relaxed, "/usr/bin/head", args=[
    "-c", "0", "/etc/passwd",
  ])
  println("same tool after granting read: \{retried.to_json()}")
  if retried.status != Exited(0) {
    raise DemoFailure("granted file read still failed")
  }
}

///|
extern "C" fn exit_ffi(code : Int) -> Unit = "moonjail_cli_exit"

///|
#borrow(message)
extern "C" fn error_ffi(message : Bytes) -> Unit = "moonjail_cli_error"

///|
extern "C" fn probe_socket_ffi() -> Int = "moonjail_cli_probe_socket"

///|
fn dispatch(args : Array[String]) -> Int raise {
  if args.length() < 2 {
    usage()
    return 2
  }
  match args[1] {
    "capabilities" => {
      show_capabilities()
      0
    }
    "explain" => {
      show_plan(true)
      0
    }
    "check" => profile_command(args, "check")
    "explain-profile" => profile_command(args, "explain-profile")
    "run" => profile_command(args, "run")
    "run-deny-socket" => run_deny_socket(args)
    "probe-socket" => {
      let errno = probe_socket_ffi()
      println("socket errno: \{errno}")
      if errno == 0 {
        0
      } else {
        1
      }
    }
    "demo" => {
      demo()
      0
    }
    _ => {
      usage()
      2
    }
  }
}

///|
fn main {
  let args = @env.args()
  let code = dispatch(args) catch {
    error => {
      error_ffi(@utf8.encode("moonjail: \{Repr(error)}"))
      3
    }
  }
  if code != 0 {
    exit_ffi(code)
  }
}
