#!/bin/sh
# Copy the read-only source mount into a private tmpfs (plus the lockfile resolved while preparing),
# then run the requested argv there.
set -eu
rm -rf /tmp/work
cp -R /src /tmp/work
cd /tmp/work
if [ -f /deps/Gemfile.lock ] && [ ! -f Gemfile.lock ]; then cp /deps/Gemfile.lock Gemfile.lock; fi
exec "$@"
