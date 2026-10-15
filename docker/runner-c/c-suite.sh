#!/bin/sh
# Runs the repository's own test suite and writes JUnit XML to /out/junit.xml.
#   CMake projects: configure + build offline, then `ctest --output-junit` (one <testcase> per CTest test).
#   Make projects:  `make test`, reported as a single <testcase> (make has no per-test results).
if [ -f CMakeLists.txt ]; then
  cmake -S . -B /tmp/build -DCMAKE_BUILD_TYPE=Debug \
    -DFETCHCONTENT_BASE_DIR=/tmp/fetch -DFETCHCONTENT_FULLY_DISCONNECTED=ON > /tmp/configure.log 2>&1 \
    || { cat /tmp/configure.log; exit 2; }
  cmake --build /tmp/build -j 2 || exit 2
  ctest --test-dir /tmp/build --output-on-failure --output-junit /out/junit.xml
  rc=$?
  [ "$rc" -eq 0 ] || rc=1
  exit $rc
fi
make test
rc=$?
if [ "$rc" -eq 0 ]; then body=''; else body='<failure message="make test failed"/>'; rc=1; fi
printf '<testsuites><testsuite name="make"><testcase classname="make" name="make test">%s</testcase></testsuite></testsuites>\n' "$body" > /out/junit.xml
exit $rc
