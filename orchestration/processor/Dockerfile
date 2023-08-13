FROM rust:1.71-slim-bookworm as builder
LABEL description="STAGE 1: Build"

# Upgrade and add dev dependencies
RUN apt update && apt upgrade -y && apt install -y pkg-config clang libssl-dev && apt autoremove -y && apt clean

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

# Add the wasm toolchain
RUN rustup target add wasm32-unknown-unknown

# Mount the caches and build
RUN --mount=type=cache,target=/root/.cargo \
  --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/usr/local/cargo/git \
  --mount=type=cache,target=/serai/target \
  cd processor && \
  cargo build --release --all-features && \
  mkdir /serai/bin && \
  mv /serai/target/release/serai-processor /serai/bin

# Prepare Image
FROM debian:bookworm-slim as image
LABEL description="STAGE 2: Copy and Run"

# Upgrade packages and install openssl
RUN apt update && apt upgrade -y && apt install -y libssl-dev

# Switch to a non-root user
RUN useradd --system --create-home --shell /sbin/nologin processor
USER processor

WORKDIR /home/processor

# Copy necessary files to run node
COPY --from=builder --chown=processsor /serai/bin/serai-processor /bin/
COPY --from=builder --chown=processsor /serai/AGPL-3.0 .

# Run processor
CMD ["serai-processor"]
