# ProofPatch sandbox image for C# (.NET): runs a cloned repository's `dotnet test` suite in isolation.
# Build once (needs network):  docker build -t proofpatch-runner:dotnet8 docker/runner-dotnet
FROM mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin runner
ENV DOTNET_CLI_HOME=/tmp DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    NUGET_PACKAGES=/deps/nuget DOTNET_GENERATE_ASPNET_CERTIFICATE=false MSBUILDDISABLENODEREUSE=1
COPY pp-run.sh /usr/local/bin/pp-run
RUN chmod 0555 /usr/local/bin/pp-run
USER 10001
ENTRYPOINT ["/usr/local/bin/pp-run"]
