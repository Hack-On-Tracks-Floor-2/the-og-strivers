# ProofPatch sandbox image: runs a cloned repository's Python test suite in isolation.
# Build once (needs network):  docker build -t proofpatch-runner:py312 docker/runner
FROM python:3.12-slim
RUN pip install --no-cache-dir "pytest>=8,<9" "bandit>=1.7,<2" \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin runner
COPY pp-run.sh /usr/local/bin/pp-run
RUN chmod 0555 /usr/local/bin/pp-run
USER 10001
ENTRYPOINT ["/usr/local/bin/pp-run"]
