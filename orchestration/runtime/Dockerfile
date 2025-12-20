# rust:1.91.1-alpine as of November 11th, 2025 (GMT)
FROM --platform=linux/amd64 rust@sha256:700c0959b23445f69c82676b72caa97ca4359decd075dca55b13339df27dc4d3 AS deterministic

RUN apk add musl-dev=1.2.5-r10

# Add the wasm toolchain
RUN rustup target add wasm32v1-none

FROM deterministic

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

# Build the runtime, copying it to the volume if it exists
ENV RUSTFLAGS="-Ctarget-feature=-crt-static"
CMD cargo build --release -p serai-runtime && \
  mkdir -p /volume && \
  cp /serai/target/release/wbuild/serai-runtime/serai_runtime.wasm /volume/serai.wasm
