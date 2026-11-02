#!/usr/bin/env sh
# Modules (src/Httpgrl.Modules.*) may only use the plugin API: no direct filesystem access (resources come
# from HttpContext.Probe/OpenFile/ListDirectory), no native interop, no process spawning, no reflection or
# assembly loading, and no project reference other than Httpgrl.Abstractions.
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
[ "$fail" -eq 0 ] && echo "module boundaries ok"
exit "$fail"
