FROM rust:1.73-slim-bookworm as builder
LABEL description="STAGE 1: Build"

# Upgrade and add dev dependencies
RUN apt update && apt upgrade -y && apt install -y pkg-config clang libssl-dev && apt autoremove -y && apt clean

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

# Mount the caches and build
RUN --mount=type=cache,target=/root/.cargo \
  --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/usr/local/cargo/git \
  --mount=type=cache,target=/serai/target \
  cd coordinator && \
  cargo build --release --all-features && \
  mkdir /serai/bin && \
  mv /serai/target/release/serai-coordinator /serai/bin

# Also build mimalloc
FROM debian:bookworm-slim as mimalloc

RUN apt update && apt upgrade -y && apt install -y gcc g++ make cmake git
RUN git clone https://github.com/microsoft/mimalloc && \
  cd mimalloc && \
  mkdir -p out/secure && \
  cd out/secure && \
  cmake -DMI_SECURE=ON ../.. && \
  make && \
  cp ./libmimalloc-secure.so ../../../libmimalloc.so

# Build the actual image
FROM debian:bookworm-slim as image

COPY --from=mimalloc libmimalloc.so /usr/lib
RUN echo "/usr/lib/libmimalloc.so" >> /etc/ld.so.preload

# Upgrade packages and install openssl
RUN apt update && apt upgrade -y && apt install -y libssl-dev && apt autoremove && apt clean

# Switch to a non-root user
RUN useradd --system --create-home --shell /sbin/nologin coordinator
USER coordinator

WORKDIR /home/coordinator

# Copy necessary files to run node
COPY --from=builder --chown=processsor /serai/bin/serai-coordinator /bin/
COPY --from=builder --chown=processsor /serai/AGPL-3.0 .

# Run coordinator
CMD ["serai-coordinator"]
