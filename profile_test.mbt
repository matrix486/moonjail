///|
test "version 1 policy JSON round-trips without losing rights or limits" {
  let original = @moonjail.Policy::deny_by_default(name="converter")
    .allow_syscall("read")
    .allow_syscall("write")
    .allow_path("./input", [ReadFile, ReadDir])
    .allow_path("./output", [ReadFile, WriteFile, Refer])
    .limit_cpu(2)
    .limit_memory(134217728L)
  let restored = @moonjail.Policy::from_json(original.to_json())
  assert_eq(restored, original)
  ignore(@moonjail.compile(restored, X86_64))
}

///|
test "unknown policy schema version is rejected" {
  let text = @moonjail.Policy::deny_by_default()
    .to_json()
    .replace(old="\"version\": 1", new="\"version\": 2")
  try @moonjail.Policy::from_json(text) catch {
    UnsupportedVersion(version) => assert_eq(version, 2)
    _ => fail("expected UnsupportedVersion")
  } noraise {
    _ => fail("expected schema version to fail")
  }
}

///|
test "malformed JSON cannot become a runnable policy" {
  try @moonjail.Policy::from_json("{") catch {
    InvalidJson(_) => ()
    _ => fail("expected InvalidJson")
  } noraise {
    _ => fail("expected malformed JSON to fail")
  }
}
