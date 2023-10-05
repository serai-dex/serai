FROM rust:1.73.0-slim-bookworm as builder

# Move to a Debian package snapshot
RUN rm -rf /etc/apt/sources.list.d/debian.sources && \
  rm -rf /var/lib/apt/lists/* && \
  echo "deb [arch=amd64] http://snapshot.debian.org/archive/debian/20230703T000000Z bookworm main" > /etc/apt/sources.list && \
  apt update

# Install dependencies
RUN apt install clang -y

# Add the wasm toolchain
RUN rustup target add wasm32-unknown-unknown

# Add files for build
ADD common /serai/common
ADD crypto /serai/crypto
ADD coins /serai/coins
ADD message-queue /serai/message-queue
ADD processor /serai/processor
ADD coordinator /serai/coordinator
ADD substrate /serai/substrate
ADD mini /serai/mini
ADD tests /serai/tests
ADD Cargo.toml /serai
ADD Cargo.lock /serai
ADD AGPL-3.0 /serai

WORKDIR /serai
