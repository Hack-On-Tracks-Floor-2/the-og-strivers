# ProofPatch Semgrep scanner image: pinned Semgrep CLI + pinned, trusted rules baked in.
# Build once (needs network):  docker build -t proofpatch-semgrep:1.178.0 docker/runner-semgrep
# Never runs repository-provided Semgrep configs and never uses --autofix. Scans run with network=none.
FROM semgrep/semgrep:1.178.0

# semgrep-rules pinned to one commit (Semgrep Rules License v1.0). Only security rules are kept.
ARG RULES_COMMIT=9bbf021d0acffa3095fcffd17b2bc7787eb4796d
USER root
RUN mkdir -p /rules /tmp/rules-src \
 && wget -qO- "https://github.com/semgrep/semgrep-rules/archive/${RULES_COMMIT}.tar.gz" | tar -xz -C /tmp/rules-src --strip-components=1 \
 && for lang in python javascript typescript java go php ruby csharp c rust kotlin; do \
      if [ -d "/tmp/rules-src/$lang" ]; then \
        find "/tmp/rules-src/$lang" -path '*/security/*' \( -name '*.yaml' -o -name '*.yml' \) ! -name '*.test.*' \
          -exec sh -c 'for f; do d="/rules/'"$lang"'/$(dirname "${f#/tmp/rules-src/'"$lang"'/}")"; mkdir -p "$d"; cp "$f" "$d/"; done' sh {} + ; \
      fi; \
    done \
 && echo "${RULES_COMMIT}" > /rules/COMMIT \
 && rm -rf /tmp/rules-src \
 && (adduser -D -u 10001 runner 2>/dev/null || useradd --uid 10001 --create-home runner)
ENV HOME=/tmp SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 XDG_CACHE_HOME=/tmp/.cache XDG_CONFIG_HOME=/tmp/.config
COPY pp-run.sh /usr/local/bin/pp-run
RUN chmod 0555 /usr/local/bin/pp-run
USER 10001
ENTRYPOINT ["/usr/local/bin/pp-run"]
