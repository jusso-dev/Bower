# Rust bower-collector image. Build from the repository root (policies/ is shared):
#   docker build -f rust/Dockerfile -t bower-collector-rs .
# Same runtime contract as deploy/docker/Dockerfile: port 4319, UID/GID 1654,
# /var/lib/bower (queue) and /var/spool/bower (AMA spool) volumes, policies in
# /app/policies/default, so compose files and Kubernetes manifests work unchanged.
# Builds natively per platform (musl, fully static): C dependencies (SQLite, TLS)
# make cross-compiling from $BUILDPLATFORM fragile, so multi-arch builds use QEMU.
FROM rust:1.97-alpine AS build
RUN apk add --no-cache build-base musl-dev cmake perl
WORKDIR /src/rust
COPY rust/ ./
# Multi-arch builds run both platforms at once: lock the shared registry cache and
# keep one target cache per platform, or parallel unpacks fail with "File exists".
ARG TARGETPLATFORM
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/rust/target,id=bower-rust-target-${TARGETPLATFORM},sharing=locked \
    cargo build --release --locked -p bower-collector \
    && install -D -m 0755 target/release/bower-collector /out/app/bower-collector \
    && mkdir -p /out/var/lib/bower /out/var/spool/bower

# Static distroless base: CA certificates and tzdata only, no shell or package manager.
FROM gcr.io/distroless/static-debian12 AS runtime
WORKDIR /app
COPY --from=build --chown=1654:1654 /out/app/ /app/
COPY --chown=1654:1654 policies ./policies
COPY --from=build --chown=1654:1654 /out/var/ /var/
USER 1654:1654
ENV BOWER_LISTEN_URL=http://0.0.0.0:4319
ENV BOWER_QUEUE_PATH=/var/lib/bower/queue.db
ENV BOWER_POLICY_DIRECTORY=/app/policies/default
EXPOSE 4319
VOLUME ["/var/lib/bower", "/var/spool/bower"]
# No shell or curl in the image: the binary probes its own /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/app/bower-collector", "--healthcheck"]
ENTRYPOINT ["/app/bower-collector"]
