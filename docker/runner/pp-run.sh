#!/bin/sh
# Copy the read-only source mount into a private tmpfs, then run the requested argv there.
set -eu
rm -rf /tmp/work
cp -R /src /tmp/work
cd /tmp/work
exec "$@"
