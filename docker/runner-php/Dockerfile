# ProofPatch sandbox image for PHP: runs a cloned repository's PHPUnit suite in isolation.
# Build once (needs network):  docker build -t proofpatch-runner:php83 docker/runner-php
FROM php:8.3-cli-bookworm
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
RUN apt-get update && apt-get install -y --no-install-recommends unzip git && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin runner
ENV COMPOSER_HOME=/tmp/composer COMPOSER_ALLOW_SUPERUSER=0
COPY pp-run.sh /usr/local/bin/pp-run
RUN chmod 0555 /usr/local/bin/pp-run
USER 10001
ENTRYPOINT ["/usr/local/bin/pp-run"]
