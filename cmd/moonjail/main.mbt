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
fn selected_architecture() -> @sandbox.Architecture {
  if @runtime.is_supported() {
    try! @runtime.current_architecture()
  } else {
    X86_64
  }
}

///|
fn load_plan(path : String) -> @sandbox.SandboxPlan {
  let content = try! @fs.read_file_to_string(path)
  let policy = @sandbox.Policy::from_json(content) catch {
    error => {
      println("invalid profile: \{Repr(error)}")
      panic()
    }
  }
  try! @sandbox.compile(policy, selected_architecture())
}

///|
fn profile_command(args : Array[String], mode : String) -> Unit {
  if args.length() < 3 || (mode == "run" && args.length() < 4) {
    usage()
    return
  }
  let plan = load_plan(args[2])
  match mode {
    "check" => println("valid policy: \{plan.name}")
    "explain-profile" => println(plan.explain())
    "run" => {
      let result = try! @runtime.run(plan, args[3], args=command_args(args, 4))
      println(result.to_json())
    }
    _ => ()
  }
}

///|
fn show_capabilities() -> Unit {
  println(
    "platform: \{if @runtime.is_supported() { "linux" } else { "unsupported" }}",
  )
  if @runtime.is_supported() {
    println("architecture: \{Repr(try! @runtime.current_architecture())}")
    println("landlock ABI: \{@runtime.landlock_abi()}")
    println("seccomp: available")
  }
}

///|
fn show_plan(show_program : Bool) -> Unit {
  let policy = demo_file_policy()
  let architecture = if @runtime.is_supported() {
    try! @runtime.current_architecture()
  } else {
    X86_64
  }
  let plan = try! @sandbox.compile(policy, architecture)
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
fn run_deny_socket(args : Array[String]) -> Unit {
  if args.length() < 3 {
    usage()
    return
  }
  let architecture = try! @runtime.current_architecture()
  let policy = @sandbox.Policy::allow_by_default(name="deny-socket")
    .deny_syscall("socket", errno=13)
    .with_landlock_required(false)
  let plan = try! @sandbox.compile(policy, architecture)
  let result = try! @runtime.run(plan, args[2], args=command_args(args, 3))
  println(result.to_json())
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
fn demo() -> Unit {
  println("== kernel capabilities ==")
  show_capabilities()
  println("\n== policy explanation ==")
  show_plan(false)
  if @runtime.is_supported() {
    println("\n== deny socket creation ==")
    let architecture = try! @runtime.current_architecture()
    let policy = @sandbox.Policy::allow_by_default(name="demo-deny-socket")
      .deny_syscall("socket", errno=13)
      .with_landlock_required(false)
    let plan = try! @sandbox.compile(policy, architecture)
    let result = try! @runtime.run(plan, "/usr/bin/python3", args=[
      "-c", "import socket; socket.socket()",
    ])
    println("socket attempt: \{result.to_json()}")
    println("\n== Landlock file policy ==")
    if @runtime.landlock_abi() >= 3 {
      let restricted = try! @sandbox.compile(demo_file_policy(), architecture)
      let allowed = try! @runtime.run(restricted, "/usr/bin/cat", args=[
        "./runtime/fixtures/allowed.txt",
      ])
      println("declared file: \{allowed.to_json()}")
      let denied = try! @runtime.run(restricted, "/usr/bin/head", args=[
        "-c", "0", "/etc/passwd",
      ])
      println("undeclared file: \{denied.to_json()}")
      let relaxed = try! @sandbox.compile(
        demo_file_policy().allow_path("/etc/passwd", [ReadFile]),
        architecture,
      )
      let retried = try! @runtime.run(relaxed, "/usr/bin/head", args=[
        "-c", "0", "/etc/passwd",
      ])
      println("same tool after granting read: \{retried.to_json()}")
    } else {
      println("Landlock ABI 3 or newer is required for this demo")
    }
  }
}

///|
fn main {
  let args = @env.args()
  if args.length() < 2 {
    usage()
    return
  }
  match args[1] {
    "capabilities" => show_capabilities()
    "explain" => show_plan(true)
    "check" => profile_command(args, "check")
    "explain-profile" => profile_command(args, "explain-profile")
    "run" => profile_command(args, "run")
    "run-deny-socket" => run_deny_socket(args)
    "demo" => demo()
    _ => usage()
  }
}
