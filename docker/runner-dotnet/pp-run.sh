#!/bin/sh
# Copy the read-only source mount into a private tmpfs, then run the requested argv there.
# The .NET CLI's one-time setup takes a named mutex that cannot be created on a read-only root,
# so its completion markers are written up front (in the private /tmp home).
set -eu
v=$(dotnet --version)
mkdir -p /tmp/.local/share/NuGet/Migrations /tmp/.dotnet
touch /tmp/.local/share/NuGet/Migrations/1 "/tmp/.dotnet/$v.dotnetFirstUseSentinel" "/tmp/.dotnet/$v.toolpath.sentinel"
rm -rf /tmp/work
cp -R /src /tmp/work
cd /tmp/work
exec "$@"
