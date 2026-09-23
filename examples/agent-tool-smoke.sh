#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root. This models an agent invoking a file-reading
# tool while an unrelated parent descriptor refers to a disallowed file.
moon run cmd/moonjail -- check examples/read-only-tool.json
moon run cmd/moonjail -- run examples/read-only-tool.json \
  /usr/bin/sha256sum runtime/fixtures/allowed.txt

set +e
moon run cmd/moonjail -- run examples/read-only-tool.json \
  /usr/bin/sha256sum /etc/passwd
denied_status=$?
set -e
test "$denied_status" -eq 10

exec 9</etc/passwd
set +e
moon run cmd/moonjail -- run examples/read-only-tool.json \
  /usr/bin/bash -c 'read -r line <&9'
inherited_status=$?
set -e
exec 9<&-
test "$inherited_status" -eq 10
