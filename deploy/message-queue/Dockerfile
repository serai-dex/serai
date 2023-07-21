FROM rust:1.71-slim as builder
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

# Add necessary packages
RUN apt update && apt upgrade -y && apt install -y pkg-config clang libssl-dev

# Mount the caches and build
RUN --mount=type=cache,target=/root/.cargo/ \
  --mount=type=cache,target=/serai/target \
  cd message-queue && \
  cargo build --release --all-features && \
  mkdir /serai/bin && \
  mv /serai/target/release/serai-message-queue /serai/bin

# Prepare Image
FROM debian:bullseye-slim as image
LABEL description="STAGE 2: Copy and Run"

WORKDIR /home/serai

# Update for security purposes
RUN apt update && apt upgrade -y

# Copy the Message Queue binary and relevant license
COPY --from=builder /serai/bin/* /bin/
COPY --from=builder /serai/AGPL-3.0 .

# Run message-queue
EXPOSE 2287
CMD ["serai-message-queue"]
