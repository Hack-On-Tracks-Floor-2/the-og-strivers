# ProofPatch sandbox image for Go: runs a cloned repository's `go test` suite in isolation.
# Build once (needs network):  docker build -t proofpatch-runner:go122 docker/runner-go
FROM golang:1.22-bookworm
RUN GOBIN=/usr/local/bin go install gotest.tools/gotestsum@v1.12.0 \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin runner
# Modules come from the prepared dependency folder; tests never reach the network.
ENV GOMODCACHE=/deps/gomod GOCACHE=/tmp/gocache GOPATH=/tmp/go GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-buildvcs=false
COPY pp-run.sh /usr/local/bin/pp-run
RUN chmod 0555 /usr/local/bin/pp-run
USER 10001
ENTRYPOINT ["/usr/local/bin/pp-run"]
