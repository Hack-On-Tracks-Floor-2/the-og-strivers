# ProofPatch sandbox image for Java/Kotlin (Maven): runs a cloned repository's tests in isolation.
# Build once (needs network):  docker build -t proofpatch-runner:java21 docker/runner-java
FROM maven:3.9-eclipse-temurin-21
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin runner
# Dependencies come from the prepared folder (/deps/m2); tests run Maven offline.
ENV MAVEN_OPTS="-Xmx768m" MAVEN_CONFIG=/tmp/m2conf
COPY pp-run.sh /usr/local/bin/pp-run
RUN chmod 0555 /usr/local/bin/pp-run
USER 10001
ENTRYPOINT ["/usr/local/bin/pp-run"]
