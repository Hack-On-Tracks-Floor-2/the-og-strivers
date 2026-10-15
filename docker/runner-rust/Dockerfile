# ProofPatch sandbox image for Rust (cargo test): runs a cloned crate's tests in isolation.
# Build once (needs network):  docker build -t proofpatch-runner:rust180 docker/runner-rust
FROM rust:1.80-slim-bookworm
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin runner
ENV CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/tmp/target CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0
COPY pp-run.sh /usr/local/bin/pp-run
COPY cargo-junit.sh /usr/local/bin/cargo-junit
RUN chmod 0555 /usr/local/bin/pp-run /usr/local/bin/cargo-junit
USER 10001
ENTRYPOINT ["/usr/local/bin/pp-run"]
