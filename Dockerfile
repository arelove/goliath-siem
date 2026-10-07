# The goliath binary and its interface, as a small image that runs as an
# unprivileged user.
#
#   docker build -t goliath .
#
# Interface stage: installed exactly as locked, and built to static files.
FROM node:24-slim AS ui
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
WORKDIR /ui
COPY ui/package.json ui/pnpm-lock.yaml ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile
COPY ui/ ./
RUN pnpm build

# Build stage: the toolchain, what librdkafka's configure script needs for
# the Kafka feature, clang for generating RocksDB's bindings, and cargo
# caches kept between builds by BuildKit.
FROM rust:1.98-slim-bookworm AS build
RUN apt-get update \
    && apt-get install --yes --no-install-recommends clang g++ libclang-dev make perl python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# How many compilers run at once: one for every 2 GiB of memory, and never
# more than there are processors. A release compiler of this workspace takes
# a gigabyte and more, and cargo's own choice is one for every processor. On
# a machine with many processors and little memory, as Docker Desktop's
# virtual machine often is, they fill the memory, and the machine swaps
# until it stops answering. `--build-arg CARGO_BUILD_JOBS=4` chooses the
# number.
ARG CARGO_BUILD_JOBS
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --jobs "$(scripts/build-jobs.sh)" -p goliath --features kafka \
    && cp target/release/goliath /goliath
# The runtime image has no shell, so its directories are made here. A named
# volume mounted over them starts with their owner, the unprivileged user.
RUN mkdir -p /state/var/lib/goliath/data /state/var/lib/goliath/inbox

# The demo's recording generator, built only when a target asks for it:
#   docker build --target fleet -t goliath-fleet .
FROM build AS fleet-build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --jobs "$(scripts/build-jobs.sh)" -p goliath-bench --bin fleet \
    && cp target/release/fleet /fleet

FROM gcr.io/distroless/cc-debian12:nonroot AS fleet
COPY --from=fleet-build /fleet /usr/local/bin/fleet
ENTRYPOINT ["/usr/local/bin/fleet"]

# Runtime stage: glibc and CA certificates, no shell or package manager.
# Last, so that it is what a plain `docker build` produces.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /goliath /usr/local/bin/goliath
COPY --from=build --chown=65532:65532 /state/var/lib/goliath /var/lib/goliath
COPY --from=ui /ui/dist /usr/share/goliath/ui
# Topics, positions, and inboxes; a volume in compose.
WORKDIR /var/lib/goliath
USER nonroot
ENTRYPOINT ["/usr/local/bin/goliath"]
CMD ["run", "--config", "/etc/goliath/goliath.toml"]
