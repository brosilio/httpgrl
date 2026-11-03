#!/usr/bin/env bash
# Scaffold a module project: csproj (Abstractions-only reference) and its registration in the solution, the host,
# the tests and the Dockerfile restore layer. Usage: scripts/new-module-project.sh Name   (-> Httpgrl.Modules.Name)
set -euo pipefail
cd "$(dirname "$0")/.."
name="Httpgrl.Modules.$1"
dir="src/$name"
[ -e "$dir" ] && { echo "$dir exists" >&2; exit 1; }
mkdir -p "$dir"
cat > "$dir/$name.csproj" <<XML
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <RootNamespace>$name</RootNamespace>
  </PropertyGroup>
  <ItemGroup>
    <!-- Modules see only the plugin API, never the engine. -->
    <ProjectReference Include="../Httpgrl.Abstractions/Httpgrl.Abstractions.csproj" />
    <InternalsVisibleTo Include="Httpgrl.Tests" />
  </ItemGroup>
</Project>
XML
anchor='Httpgrl.Modules.Proxy/Httpgrl.Modules.Proxy.csproj'
sed -i "s|^\(\s*\)<ProjectReference Include=\"../$anchor\" />|&\n\1<ProjectReference Include=\"../$name/$name.csproj\" />|" src/Httpgrl/Httpgrl.csproj
sed -i "s|^\(\s*\)<ProjectReference Include=\"../../src/$anchor\" />|&\n\1<ProjectReference Include=\"../../src/$name/$name.csproj\" />|" tests/Httpgrl.Tests/Httpgrl.Tests.csproj
sed -i "s|^\(\s*\)<Project Path=\"src/$anchor\" />|&\n\1<Project Path=\"src/$name/$name.csproj\" />|" httpgrl.slnx
sed -i "s|^COPY src/$anchor src/Httpgrl.Modules.Proxy/|&\nCOPY src/$name/$name.csproj src/$name/|" Dockerfile
grep -c "$name" src/Httpgrl/Httpgrl.csproj tests/Httpgrl.Tests/Httpgrl.Tests.csproj httpgrl.slnx Dockerfile
echo "now add the module(s) to src/Httpgrl/Program.cs and tests/Httpgrl.Tests/Harness.cs"
