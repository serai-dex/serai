# rust:1.91.1-slim-trixie as of November 11th, 2025 (GMT)
FROM --platform=linux/amd64 rust@sha256:ccdbe08a0b10498bc5f3cac3d736af7b8eb6cb0ecfc1e8a504e93d8ee76a8e8e AS deterministic

# Move to a Debian package snapshot
RUN rm -rf /etc/apt/sources.list.d/debian.sources && \
  rm -rf /var/lib/apt/lists/* && \
  echo "deb [arch=amd64] http://snapshot.debian.org/archive/debian/20251111T000000Z trixie main" > /etc/apt/sources.list && \
  apt update

# Install dependencies
RUN apt update -y && apt upgrade -y && apt install -y clang

# Add the wasm toolchain
RUN rustup component add rust-src
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
ADD mini /serai/mini
ADD tests /serai/tests
ADD Cargo.toml /serai
ADD Cargo.lock /serai
ADD AGPL-3.0 /serai

WORKDIR /serai

# Build the runtime, copying it to the volume if it exists
CMD cargo build --release -p serai-runtime && \
  mkdir -p /volume && \
  cp /serai/target/release/wbuild/serai-runtime/serai_runtime.wasm /volume/serai.wasm
