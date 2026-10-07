# Build on the runner's native platform and cross-compile for TARGETARCH (no QEMU).
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0.401 AS build
ARG TARGETARCH
WORKDIR /src
COPY . .
RUN dotnet restore Bower.sln --locked-mode
# Framework-dependent for container runtime image (not self-contained single-file).
# RID follows the target platform so native SQLite matches the runtime image.
RUN RID="linux-$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64)" \
    && dotnet publish src/Bower.Collector/Bower.Collector.csproj \
    --configuration Release \
    --no-restore \
    --runtime "$RID" \
    --self-contained false \
    -p:PublishSingleFile=false \
    --output /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0.12 AS runtime
WORKDIR /app
COPY --from=build /app .
COPY policies ./policies
RUN mkdir -p /var/lib/bower /var/spool/bower \
    && chown -R 1654:1654 /app /var/lib/bower /var/spool/bower
USER 1654
# Bower sets its own listen URL; clear the base image default to avoid an override warning.
ENV ASPNETCORE_HTTP_PORTS=
ENV BOWER_LISTEN_URL=http://0.0.0.0:4319
ENV BOWER_QUEUE_PATH=/var/lib/bower/queue.db
ENV BOWER_POLICY_DIRECTORY=/app/policies/default
EXPOSE 4319
VOLUME ["/var/lib/bower", "/var/spool/bower"]
ENTRYPOINT ["dotnet", "Bower.Collector.dll"]
