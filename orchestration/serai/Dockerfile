FROM rust:1.73-slim-bookworm as builder
LABEL description="STAGE 1: Build"

# Upgrade and add dev dependencies
RUN apt update && apt upgrade -y && apt install -y git pkg-config make clang libssl-dev protobuf-compiler && apt autoremove -y && apt clean

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
  cd substrate/node && \
  cargo build --release && \
  mkdir /serai/bin && \
  mv /serai/target/release/serai-node /serai/bin

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

# Upgrade packages
RUN apt update && apt upgrade -y

# Switch to a non-root user
RUN useradd --system --home /home/serai --shell /sbin/nologin serai
USER serai

WORKDIR /home/serai

# Copy necessary files to run node
COPY --from=builder --chown=serai /serai/bin/serai-node /bin/
COPY --from=builder --chown=serai /serai/AGPL-3.0 .

# Run node
EXPOSE 30333 9615 9933 9944
CMD ["serai-node"]
