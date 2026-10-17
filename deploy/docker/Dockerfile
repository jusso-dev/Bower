# Bower collector, published as a Native AOT executable (no .NET runtime in the image).
# Build on the runner's native platform and cross-compile for TARGETARCH (no QEMU): the
# -aot SDK image carries the native toolchain and the cross-architecture sysroot.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0.401-noble-aot AS build
ARG TARGETARCH
WORKDIR /src
COPY . .
RUN dotnet restore src/Bower.Collector/Bower.Collector.csproj --locked-mode
# RID follows the target platform so the native binary and SQLite match the runtime image.
RUN RID="linux-$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64)" \
    && dotnet publish src/Bower.Collector/Bower.Collector.csproj \
        --configuration Release \
        --no-restore \
        --runtime "$RID" \
        --output /app \
    && rm -f /app/*.dbg /app/*.pdb \
    && mkdir -p /state/lib /state/spool

# Chiseled runtime-deps: no shell, no package manager, no ICU (InvariantGlobalization).
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0.13-noble-chiseled AS runtime
WORKDIR /app
COPY --from=build /app .
COPY policies ./policies
COPY --from=build --chown=1654:1654 /state/lib /var/lib/bower
COPY --from=build --chown=1654:1654 /state/spool /var/spool/bower
USER 1654:1654
# Bower sets its own listen URL; clear the base image default to avoid an override warning.
ENV ASPNETCORE_HTTP_PORTS= \
    BOWER_LISTEN_URL=http://0.0.0.0:4319 \
    BOWER_QUEUE_PATH=/var/lib/bower/queue.db \
    BOWER_POLICY_DIRECTORY=/app/policies/default \
    DOTNET_gcServer=0
EXPOSE 4319
VOLUME ["/var/lib/bower", "/var/spool/bower"]
ENTRYPOINT ["/app/Bower.Collector"]
