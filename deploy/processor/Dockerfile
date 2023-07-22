FROM docker.io/paritytech/ci-linux:production as builder
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
FROM debian:bullseye as image
LABEL description="STAGE 2: Copy and Run"

WORKDIR /home/serai

# Copy necessary files to run node
COPY --from=builder /serai/bin/* /bin/
COPY --from=builder /serai/AGPL-3.0 .

# Run processor
CMD ["serai-processor"]
