#!/bin/sh
# Copy the read-only source mount into a private tmpfs. Maven's local repository is copied too,
# because Maven writes bookkeeping files into it even when offline.
set -eu
rm -rf /tmp/work
cp -R /src /tmp/work
if [ -d /deps/m2 ] && [ ! -d /tmp/m2 ]; then cp -R /deps/m2 /tmp/m2; fi
cd /tmp/work
exec "$@"
