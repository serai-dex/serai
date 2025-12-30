# syntax=docker/dockerfile:1
# check=skip=FromPlatformFlagConstDisallowed;error=true
# We want to explicitly set the platform to ensure a constant host environment

# rust:1.92.0-alpine3.23 as of December 20th, 2025 (GMT)
FROM --platform=linux/amd64 rust@sha256:7edc8cde436939b5350f9fafbffc43f0f957b8506ad94aa8e1336f0799fa845f AS builder

# Add Rust's source, as necessary to `build-std` as we do for the WASM
RUN rustup component add rust-src

# Add files for build
ADD patches /serai/patches
ADD common /serai/common
ADD crypto /serai/crypto
ADD networks /serai/networks
ADD message-queue /serai/message-queue
ADD processor /serai/processor
ADD coordinator /serai/coordinator
ADD substrate /serai/substrate
ADD orchestration/Cargo.toml /serai/orchestration/Cargo.toml
ADD orchestration/src /serai/orchestration/src
ADD tests /serai/tests
ADD Cargo.toml /serai
ADD Cargo.lock /serai
ADD AGPL-3.0 /serai

WORKDIR /serai

# Build the runtime
RUN cargo build --release -p serai-runtime --no-default-features

# Copy the artifact to its own image which solely exists to further export it
FROM busybox:musl
# Copy the artifact itself
COPY --from=builder /serai/target/release/serai_runtime.wasm /serai.wasm
# By default, copy the artifact to `/volume`, presumably a provided volume
CMD ["busybox", "cp", "/serai.wasm", "/volume/serai.wasm"]
