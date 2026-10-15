#!/bin/sh
# Copy the read-only source mount (and the prepared cargo registry, which cargo locks and writes)
# into a private tmpfs, then run the requested argv there.
set -eu
rm -rf /tmp/work
cp -R /src /tmp/work
if [ -d /deps/cargo ] && [ ! -d /tmp/cargo ]; then cp -R /deps/cargo /tmp/cargo; fi
cd /tmp/work
if [ -f /deps/Cargo.lock ] && [ ! -f Cargo.lock ]; then cp /deps/Cargo.lock Cargo.lock; fi
exec "$@"
