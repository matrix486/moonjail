///|
priv struct ActionDocument {
  kind : String
  errno : Int?
} derive(FromJson, ToJson)

///|
priv struct SyscallDocument {
  name : String
  action : ActionDocument
} derive(FromJson, ToJson)

///|
priv struct PathDocument {
  path : String
  rights : Array[String]
} derive(FromJson, ToJson)

///|
priv struct LimitsDocument {
  cpu_seconds : Int?
  address_space_bytes : Int64?
  file_size_bytes : Int64?
  open_files : Int?
  processes : Int?
} derive(FromJson, ToJson)

///|
priv struct PolicyDocument {
  version : Int
  name : String
  default_action : ActionDocument
  syscall_rules : Array[SyscallDocument]
  path_rules : Array[PathDocument]
  limits : LimitsDocument
  require_landlock : Bool
} derive(FromJson, ToJson)

///|
pub(all) suberror ProfileError {
  InvalidJson(String)
  UnsupportedVersion(Int)
  InvalidAction(String)
  InvalidRight(String)
} derive(Debug)

///|
pub extend ProfileError with @moonbitlang/core/debug.Debug::{to_repr}

///|
fn parse_action(document : ActionDocument) -> SeccompAction raise ProfileError {
  match document.kind {
    "allow" => Allow
    "errno" =>
      match document.errno {
        Some(errno) => Errno(errno)
        None => raise InvalidAction("errno action requires an errno value")
      }
    "trap" => Trap
    "log" => Log
    "kill_process" => KillProcess
    other => raise InvalidAction(other)
  }
}

///|
fn write_action(action : SeccompAction) -> ActionDocument {
  match action {
    Allow => { kind: "allow", errno: None, }
    Errno(errno) => { kind: "errno", errno: Some(errno), }
    Trap => { kind: "trap", errno: None, }
    Log => { kind: "log", errno: None, }
    KillProcess => { kind: "kill_process", errno: None, }
  }
}

///|
fn parse_right(name : String) -> AccessRight raise ProfileError {
  match name {
    "read_file" => ReadFile
    "read_dir" => ReadDir
    "write_file" => WriteFile
    "remove" => Remove
    "make_node" => MakeNode
    "execute" => Execute
    "refer" => Refer
    _ => raise InvalidRight(name)
  }
}

///|
fn write_right(right : AccessRight) -> String {
  match right {
    ReadFile => "read_file"
    ReadDir => "read_dir"
    WriteFile => "write_file"
    Remove => "remove"
    MakeNode => "make_node"
    Execute => "execute"
    Refer => "refer"
  }
}

///|
/// Parse the version 1 JSON policy schema. The result is still validated and
/// compiled before it can be used by the runtime.
pub fn Policy::from_json(text : String) -> Policy raise ProfileError {
  let json = @json.parse(text) catch {
    error => raise InvalidJson(error.to_string())
  }
  let document : PolicyDocument = @json.from_json(json) catch {
    error => raise InvalidJson(error.to_string())
  }
  if document.version != 1 {
    raise UnsupportedVersion(document.version)
  }
  let syscall_rules : Array[SyscallRule] = []
  for rule in document.syscall_rules {
    syscall_rules.push({ name: rule.name, action: parse_action(rule.action), })
  }
  let path_rules : Array[PathRule] = []
  for rule in document.path_rules {
    let rights : Array[AccessRight] = []
    for right in rule.rights {
      rights.push(parse_right(right))
    }
    path_rules.push({ path: rule.path, rights, })
  }
  {
    name: document.name,
    default_action: parse_action(document.default_action),
    syscall_rules,
    path_rules,
    limits: {
      cpu_seconds: document.limits.cpu_seconds,
      address_space_bytes: document.limits.address_space_bytes,
      file_size_bytes: document.limits.file_size_bytes,
      open_files: document.limits.open_files,
      processes: document.limits.processes,
    },
    require_landlock: document.require_landlock,
  }
}

///|
/// Serialize a policy using the stable version 1 JSON document schema.
pub fn Policy::to_json(self : Policy) -> String {
  let syscall_rules : Array[SyscallDocument] = []
  for rule in self.syscall_rules {
    syscall_rules.push({ name: rule.name, action: write_action(rule.action), })
  }
  let path_rules : Array[PathDocument] = []
  for rule in self.path_rules {
    let rights : Array[String] = []
    for right in rule.rights {
      rights.push(write_right(right))
    }
    path_rules.push({ path: rule.path, rights, })
  }
  let document : PolicyDocument = {
    version: 1,
    name: self.name,
    default_action: write_action(self.default_action),
    syscall_rules,
    path_rules,
    limits: {
      cpu_seconds: self.limits.cpu_seconds,
      address_space_bytes: self.limits.address_space_bytes,
      file_size_bytes: self.limits.file_size_bytes,
      open_files: self.limits.open_files,
      processes: self.limits.processes,
    },
    require_landlock: self.require_landlock,
  }
  @json.to_json(document).stringify(indent=2)
}
