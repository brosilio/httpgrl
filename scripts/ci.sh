#!/usr/bin/env sh
# Full verification: module boundary check, warnings-as-errors build, tests on the JIT, then the same tests as a native AOT
# binary (the engine exactly as it ships), then the AOT server binary itself.
set -eu
cd "$(dirname "$0")/.."
RID="${RID:-$(dotnet --info | sed -n 's/^ *RID: *//p' | head -n1)}"

scripts/check-boundaries.sh
dotnet build -c Release
dotnet run -c Release --no-build --project tests/Httpgrl.Tests
dotnet publish tests/Httpgrl.Tests -c Release -r "$RID" -p:PublishAot=true -o artifacts/tests-aot
artifacts/tests-aot/Httpgrl.Tests
dotnet publish src/Httpgrl -c Release -r "$RID" -o "artifacts/$RID"
"artifacts/$RID/httpgrl" -t -c conf/httpgrl.conf
echo "ok: artifacts/$RID/httpgrl"
