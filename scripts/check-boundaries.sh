#!/usr/bin/env sh
# Modules (src/Httpgrl.Modules.*) may only use the plugin API: no direct filesystem access (resources come
# from HttpContext.Probe/OpenFile/ListDirectory), no native interop, no process spawning, no reflection or
# assembly loading, and no project reference other than Httpgrl.Abstractions.
# Protocol libraries (Httpgrl.HttpFields, Httpgrl.Quic, Httpgrl.Http3) may reference only each other, in one direction.
set -eu
cd "$(dirname "$0")/.."
fail=0

banned='\b(File|Directory|Path|RandomAccess|DriveInfo|FileSystemInfo|Process|NativeLibrary|Assembly|AssemblyLoadContext|Activator)\.[A-Z]'
banned="$banned"'|new +(FileInfo|DirectoryInfo|FileStream|StreamReader|StreamWriter|FileSystemWatcher)\b'
banned="$banned"'|\b(SafeFileHandle|DllImport|LibraryImport|UnmanagedCallersOnly)\b|using +System\.(Reflection|Diagnostics\.Process)'

for dir in src/Httpgrl.Modules.*; do
    [ -d "$dir" ] || continue
    if hits=$(grep -rnE "$banned" "$dir" --include='*.cs' | grep -v '/obj/' | grep -v '/bin/'); then
        echo "module boundary violation (use the HttpContext resource API):"
        echo "$hits"
        fail=1
    fi
    for proj in "$dir"/*.csproj; do
        if grep -E '<(ProjectReference|PackageReference)' "$proj" | grep -vq 'Httpgrl.Abstractions.csproj'; then
            echo "module boundary violation: $proj references something other than Httpgrl.Abstractions"
            fail=1
        fi
    done
done

# Protocol libraries (docs/development.md, "Design decisions"): Httpgrl.HttpFields and Httpgrl.Quic reference nothing of ours,
# Httpgrl.Http3 only those two. None of them may reach into Core or Abstractions, and none lets Core see its internals:
# the server uses them through their public API, like any other consumer.
check_lib() { # project, allowed references (regex)
    proj="src/$1/$1.csproj"
    refs=$(grep -oE '<(ProjectReference|PackageReference) Include="[^"]*"' "$proj" | sed 's/.*Include="//; s/"$//' || true)
    for r in $refs; do
        if ! echo "$r" | grep -qE "^($2)$"; then
            echo "library boundary violation: $proj references $r"
            fail=1
        fi
    done
    if grep -rnE 'Httpgrl\.(Core|Abstractions)\b|\bnamespace Httpgrl;' "src/$1" --include='*.cs' | grep -v '/obj/' | grep -v '/bin/'; then
        echo "library boundary violation: $1 uses Httpgrl.Core or Httpgrl.Abstractions"
        fail=1
    fi
    if grep -qE 'InternalsVisibleTo Include="Httpgrl\.(Core|Http3|Quic|HttpFields)"' "$proj"; then
        echo "library boundary violation: $proj shows its internals to another httpgrl project"
        fail=1
    fi
}
check_lib Httpgrl.HttpFields 'NONE'
check_lib Httpgrl.Quic 'NONE'
check_lib Httpgrl.Http3 '\.\./Httpgrl\.Quic/Httpgrl\.Quic\.csproj|\.\./Httpgrl\.HttpFields/Httpgrl\.HttpFields\.csproj'

[ "$fail" -eq 0 ] && echo "module and library boundaries ok"
exit "$fail"
