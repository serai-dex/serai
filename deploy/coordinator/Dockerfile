FROM docker.io/paritytech/base-ci-linux:latest as builder
LABEL description="STAGE 1: Build"

# Update Rust
RUN rustup update

# Add files for build
ADD common /serai/common
ADD crypto /serai/crypto
ADD coins /serai/coins
ADD coordinator /serai/coordinator
ADD AGPL-3.0 /serai

WORKDIR /serai/coordinator

# Mount cargo and serai cache for Cache & Build
RUN --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/serai/coordinator/target/release/build \
    --mount=type=cache,target=/serai/coordinator/target/release/deps \
    --mount=type=cache,target=/serai/coordinator/target/release/.fingerprint \
    --mount=type=cache,target=/serai/coordinator/target/release/incremental \
    --mount=type=cache,target=/serai/coordinator/target/release/wbuild \
    --mount=type=cache,target=/serai/coordinator/target/release/lib* \
    cargo build --release

# Prepare Image
FROM ubuntu:latest as image
LABEL description="STAGE 2: Copy and Run"

WORKDIR /home/coordinator

# Copy necessary files to run node
COPY --from=builder /serai/coordinator/target/release/ /bin/
COPY --from=builder /serai/AGPL-3.0 .
CMD ["serai-coordinator"]
