#!/bin/sh
# Copy the read-only source mount (and any CMake FetchContent sources downloaded while preparing)
# into a private tmpfs, then run the requested argv there.
set -eu
rm -rf /tmp/work
cp -R /src /tmp/work
if [ -d /deps/fetch ] && [ ! -d /tmp/fetch ]; then cp -R /deps/fetch /tmp/fetch; fi
cd /tmp/work
exec "$@"
