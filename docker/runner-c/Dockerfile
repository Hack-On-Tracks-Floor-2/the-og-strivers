# ProofPatch sandbox image for C and C++: builds with CMake (or make), runs CTest / `make test`,
# and compiles standalone security tests with AddressSanitizer + UBSan.
# Build once (needs network):  docker build -t proofpatch-runner:c13 docker/runner-c
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake ca-certificates git pkg-config \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin runner
# LeakSanitizer needs ptrace, which the sandbox drops: memory errors are still caught, leaks are not.
ENV ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
COPY pp-run.sh /usr/local/bin/pp-run
COPY c-suite.sh /usr/local/bin/c-suite
COPY c-security-test.sh /usr/local/bin/c-security-test
RUN chmod 0555 /usr/local/bin/pp-run /usr/local/bin/c-suite /usr/local/bin/c-security-test
USER 10001
ENTRYPOINT ["/usr/local/bin/pp-run"]
