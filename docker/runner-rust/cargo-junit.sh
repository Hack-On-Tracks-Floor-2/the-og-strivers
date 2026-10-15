#!/bin/sh
# Runs `cargo test` (arguments are passed through) and converts its "test x ... ok|FAILED|ignored"
# lines into JUnit XML at /out/junit.xml.
cargo test --offline "$@" -- --test-threads=1 2>&1 | tee /tmp/cargo-test.txt
rc=$(grep -q '^test result: FAILED\|^error' /tmp/cargo-test.txt && echo 1 || echo 0)
grep -q '^test result:' /tmp/cargo-test.txt || rc=2
{
  echo '<testsuites><testsuite name="cargo">'
  sed -n 's/^test \(.*\) \.\.\. \(ok\|FAILED\|ignored\)$/\1|\2/p' /tmp/cargo-test.txt | while IFS='|' read -r name status; do
    case "$status" in
      ok) echo "<testcase classname=\"cargo\" name=\"$name\"></testcase>" ;;
      ignored) echo "<testcase classname=\"cargo\" name=\"$name\"><skipped/></testcase>" ;;
      *) echo "<testcase classname=\"cargo\" name=\"$name\"><failure message=\"failed\"/></testcase>" ;;
    esac
  done
  echo '</testsuite></testsuites>'
} > /out/junit.xml
exit $rc
