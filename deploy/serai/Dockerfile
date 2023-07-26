FROM rust:1.71-slim-bookworm as builder
LABEL description="STAGE 1: Build"

# Add files for build
ADD common /serai/common
ADD crypto /serai/crypto
ADD coins /serai/coins
ADD message-queue /serai/message-queue
ADD processor /serai/processor
ADD coordinator /serai/coordinator
ADD substrate /serai/substrate
ADD tests /serai/tests
ADD Cargo.toml /serai
ADD Cargo.lock /serai
ADD AGPL-3.0 /serai

WORKDIR /serai

RUN apt update && apt upgrade -y && apt install -y git pkg-config make clang libssl-dev protobuf-compiler

# Add the wasm toolchain
RUN rustup target add wasm32-unknown-unknown

# Mount the caches and build
RUN --mount=type=cache,target=/root/.cargo \
  --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/usr/local/cargo/git \
  --mount=type=cache,target=/serai/target \
  cd substrate/node && \
  cargo build --release && \
  mkdir /serai/bin && \
  mv /serai/target/release/serai-node /serai/bin

# Prepare Image
FROM debian:bookworm-slim as image
LABEL description="STAGE 2: Copy and Run"

WORKDIR /home/serai

# Copy necessary files to run node
COPY --from=builder /serai/bin/serai-node /bin/
COPY --from=builder /serai/AGPL-3.0 .

# Upgrade packages
RUN apt update && apt upgrade -y

# Run node
EXPOSE 30333 9615 9933 9944
CMD ["serai-node"]
