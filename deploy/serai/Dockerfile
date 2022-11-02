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

RUN apt update && apt upgrade -y && apt install -y make clang libssl-dev protobuf-compiler

<<<<<<< HEAD
# Add the wasm toolchain
RUN rustup target add wasm32-unknown-unknown

# Mount the caches and build
RUN --mount=type=cache,target=/root/.cargo \
  --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/usr/local/cargo/git \
  --mount=type=cache,target=/serai/target \
  cd substrate/node && cargo build --release

=======
# Install Solc @ 0.8.16
RUN pip3 install solc-select==0.2.1
RUN solc-select install 0.8.16
RUN solc-select use 0.8.16

# Mount cargo and serai cache for Cache & Build
RUN --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/serai/target/release/build \
    --mount=type=cache,target=/serai/target/release/deps \
    --mount=type=cache,target=/serai/target/release/.fingerprint \
    --mount=type=cache,target=/serai/target/release/incremental \
    --mount=type=cache,target=/serai/target/release/wbuild \
    --mount=type=cache,target=/serai/target/release/lib* \
    cargo build --release

>>>>>>> e3fc3f28 (Configure node for a multi-node testnet)
# Prepare Image
FROM debian:bookworm-slim as image
LABEL description="STAGE 2: Copy and Run"

WORKDIR /home/serai

# Copy necessary files to run node
COPY --from=builder /serai/target/release/ /bin/
COPY --from=builder /serai/AGPL-3.0 .

# Upgrade packages
RUN apt update && apt upgrade -y

# Run node
EXPOSE 30333 9615 9933 9944
CMD ["serai-node"]
