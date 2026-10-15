#!/bin/sh
# Copy the read-only source mount into a private tmpfs, link the dependencies installed in the
# preparation stage (/deps/node_modules, read-only), then run the requested argv there.
set -eu
rm -rf /tmp/work
cp -R /src /tmp/work
cd /tmp/work
if [ -d /deps/node_modules ] && [ ! -e node_modules ]; then ln -s /deps/node_modules node_modules; fi
exec "$@"
