# ProofPatch sandbox image for Ruby (Bundler + RSpec): runs a cloned repository's specs in isolation.
# Build once (needs network):  docker build -t proofpatch-runner:ruby33 docker/runner-ruby
FROM ruby:3.3-bookworm
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin runner
ENV BUNDLE_PATH=/deps/bundle BUNDLE_APP_CONFIG=/tmp/bundle-config BUNDLE_DISABLE_SHARED_GEMS=true GEM_HOME=/tmp/gems
COPY pp-run.sh /usr/local/bin/pp-run
COPY rspec2junit.rb /usr/local/bin/rspec2junit.rb
COPY rspec-junit.sh /usr/local/bin/rspec-junit
RUN chmod 0555 /usr/local/bin/pp-run /usr/local/bin/rspec-junit /usr/local/bin/rspec2junit.rb
USER 10001
ENTRYPOINT ["/usr/local/bin/pp-run"]
