#!/bin/sh
# Runs RSpec (arguments = optional spec paths) and writes JUnit XML to /out/junit.xml.
bundle exec rspec --format progress --format json --out /tmp/rspec.json "$@"
rc=$?
ruby /usr/local/bin/rspec2junit.rb /tmp/rspec.json > /out/junit.xml 2>/dev/null || true
exit $rc
