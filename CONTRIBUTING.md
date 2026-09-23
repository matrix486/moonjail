# Contributing to MoonJail

MoonJail is security-sensitive. A change to policy compilation or the native
shim should include a test that distinguishes the intended allowed and denied
behavior. Keep the C shim limited to kernel calls and process setup; policy
decisions belong in MoonBit.

## Development

Install the current MoonBit toolchain. On Linux, install a C compiler and
Linux kernel headers. Then run:

```sh
moon fmt --check
moon check --target all --warn-list +unnecessary_annotation
moon test --target native
moon build --target native
```

The portable compiler can be developed on Windows or macOS. Linux integration
tests run only when a Linux host and the required kernel features are present.
Use `moon run cmd/moonjail -- capabilities` to inspect the local host.

For a sandbox change, include a failing or denied case as well as a successful
case. Check the exact syscall numbers against Linux UAPI headers for both
x86_64 and aarch64. Keep the public JSON schema versioned; changing a field's
meaning requires a new schema version.

Please open an issue before substantially changing the public policy model.
Security reports should follow [SECURITY.md](SECURITY.md).
