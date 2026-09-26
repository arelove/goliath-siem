# The goliath binary, as a small image that runs as an unprivileged user.
#
#   docker build -t goliath .
#
# Build stage: the toolchain, what librdkafka's configure script needs for
# the Kafka feature, and cargo caches kept between builds by BuildKit.
FROM rust:1.98-slim-bookworm AS build
RUN apt-get update \
    && apt-get install --yes --no-install-recommends g++ make perl python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p goliath --features kafka \
    && cp target/release/goliath /goliath
# The runtime image has no shell, so its directories are made here. A named
# volume mounted over them starts with their owner, the unprivileged user.
RUN mkdir -p /state/var/lib/goliath/data /state/var/lib/goliath/inbox

# Runtime stage: glibc and CA certificates, no shell or package manager.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /goliath /usr/local/bin/goliath
COPY --from=build --chown=65532:65532 /state/var/lib/goliath /var/lib/goliath
# Topics, positions, and inboxes; a volume in compose.
WORKDIR /var/lib/goliath
USER nonroot
ENTRYPOINT ["/usr/local/bin/goliath"]
CMD ["run", "--config", "/etc/goliath/goliath.toml"]
