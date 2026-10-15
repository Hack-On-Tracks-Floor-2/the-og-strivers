#!/bin/sh
# Copy the read-only source mount into a private tmpfs, add the dependencies installed in the
# preparation stage and regenerate the autoloader offline for this copy, then run the argv there.
set -eu
rm -rf /tmp/work
cp -R /src /tmp/work
cd /tmp/work
if [ -d /deps/vendor ] && [ ! -e vendor ]; then
  cp -R /deps/vendor vendor
  composer dump-autoload --no-scripts --no-plugins -q 2>/dev/null || true
fi
exec "$@"
