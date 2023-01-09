FROM docker.io/paritytech/base-ci-linux:latest as builder
LABEL description="STAGE 1: Build"

# Add files for build
ADD common /serai/common
ADD crypto /serai/crypto
ADD coins /serai/coins
ADD coordinator /serai/coordinator
ADD AGPL-3.0 /serai

WORKDIR /serai/coordinator

# Update Rust
RUN rustup update
RUN rustup toolchain install nightly
RUN rustup install nightly
RUN rustup target add wasm32-unknown-unknown --toolchain nightly

# Mount cargo and serai cache for Cache & Build
RUN --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/target/release/build \
    --mount=type=cache,target=/target/release/deps \
    --mount=type=cache,target=/target/release/.fingerprint \
    --mount=type=cache,target=/target/release/incremental \
    --mount=type=cache,target=/target/release/wbuild \
    --mount=type=cache,target=/target/release/lib* \
    cargo +nightly build --release

# Prepare Image
FROM ubuntu:latest as image
LABEL description="STAGE 2: Copy and Run"

WORKDIR /home/coordinator

# Copy necessary files to run node
COPY --from=builder /serai/coordinator/target/release/ /bin/
COPY --from=builder /serai/AGPL-3.0 .
CMD ["serai-coordinator"]
