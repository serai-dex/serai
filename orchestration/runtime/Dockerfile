# rust:1.79.0-slim-bookworm as of June 13th, 2024 (GMT)
FROM --platform=linux/amd64 rust@sha256:eb37f58646a901dc7727cf448cae36daaefaba79de33b5058dab79aa4c04aefb as deterministic

# Move to a Debian package snapshot
RUN rm -rf /etc/apt/sources.list.d/debian.sources && \
  rm -rf /var/lib/apt/lists/* && \
  echo "deb [arch=amd64] http://snapshot.debian.org/archive/debian/20240301T000000Z bookworm main" > /etc/apt/sources.list && \
  apt update

# Install dependencies
RUN apt update && apt upgrade && apt install clang -y

# Add the wasm toolchain
RUN rustup target add wasm32-unknown-unknown

FROM deterministic

# Add files for build
ADD patches /serai/patches
ADD common /serai/common
ADD crypto /serai/crypto
ADD coins /serai/coins
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
