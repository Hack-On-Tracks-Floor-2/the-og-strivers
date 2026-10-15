#!/bin/sh
# Compiles one standalone security test (which #includes the code under test and has its own main)
# with AddressSanitizer + UBSan, runs it, and writes a one-case JUnit report to /out/junit.xml.
# Exit codes: 0 = attack blocked, 1 = attack worked / memory error (test failed), 2 = did not compile.
test_file="$1"
case "$test_file" in
  *.c) cc_bin=cc; std=-std=gnu11 ;;
  *) cc_bin=c++; std=-std=gnu++17 ;;
esac
includes="-I. -Iinclude -Isrc -I$(dirname "$test_file")"
for d in */include; do [ -d "$d" ] && includes="$includes -I$d"; done
if ! $cc_bin $std -g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined $includes \
     "$test_file" -o /tmp/proofpatch_security -lm 2> /tmp/compile.log; then
  cat /tmp/compile.log
  printf '<testsuites><testsuite name="security"><testcase classname="security" name="compile"><error message="did not compile"/></testcase></testsuite></testsuites>\n' > /out/junit.xml
  exit 2
fi
# GCC's ASan runtime occasionally dies at startup with only "DEADLYSIGNAL" when the kernel's address
# randomisation collides with its shadow memory. That is not a finding: retry it (a real memory bug
# always prints "ERROR: AddressSanitizer" or a UBSan "runtime error" and is never retried).
attempt=1
while :; do
  timeout 60 /tmp/proofpatch_security > /tmp/security.log 2>&1
  rc=$?
  if [ "$rc" -ne 0 ] && grep -q 'DEADLYSIGNAL' /tmp/security.log \
     && ! grep -q 'ERROR: AddressSanitizer\|runtime error' /tmp/security.log && [ "$attempt" -lt 5 ]; then
    attempt=$((attempt + 1))
    continue
  fi
  break
done
grep -v 'DEADLYSIGNAL' /tmp/security.log | head -c 20000
if [ "$rc" -eq 0 ]; then body=''; else body="<failure message=\"exit $rc\"/>"; fi
printf '<testsuites><testsuite name="security"><testcase classname="security" name="%s">%s</testcase></testsuite></testsuites>\n' "$(basename "$test_file")" "$body" > /out/junit.xml
[ "$rc" -eq 0 ] && exit 0 || exit 1
