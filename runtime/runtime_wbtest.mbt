///|
test "path policy fails closed without Landlock ABI 3" {
  let plan = @moonjail.compile(
    @moonjail.Policy::allow_by_default().allow_read("./runtime/fixtures"),
    X86_64,
  )
  try check_landlock(plan, 0) catch {
    LandlockUnavailable => ()
    _ => fail("expected LandlockUnavailable")
  } noraise {
    _ => fail("path restrictions must not silently degrade")
  }
  check_landlock(plan, 3)
}
