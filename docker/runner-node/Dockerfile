# ProofPatch sandbox image for JavaScript: runs a cloned repository's Node.js test suite in isolation.
# Build once (needs network):  docker build -t proofpatch-runner:node22 docker/runner-node
FROM node:22-slim
RUN userdel -r node 2>/dev/null || true \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin runner
COPY pp-run.sh /usr/local/bin/pp-run
RUN chmod 0555 /usr/local/bin/pp-run
USER 10001
ENTRYPOINT ["/usr/local/bin/pp-run"]
