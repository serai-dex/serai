FROM debian:bookworm-slim as mimalloc

RUN apt update && apt upgrade -y && apt install -y gcc g++ make cmake git
RUN git clone https://github.com/microsoft/mimalloc && \
  cd mimalloc && \
  git checkout 43ce4bd7fd34bcc730c1c7471c99995597415488 && \
  mkdir -p out/secure && \
  cd out/secure && \
  cmake -DMI_SECURE=ON ../.. && \
  make && \
  cp ./libmimalloc-secure.so ../../../libmimalloc.so
FROM rust:1.74-slim-bookworm as builder

COPY --from=mimalloc libmimalloc.so /usr/lib
RUN echo "/usr/lib/libmimalloc.so" >> /etc/ld.so.preload

RUN apt update && apt upgrade -y && apt autoremove -y && apt clean

# Add dev dependencies
RUN apt install -y pkg-config clang

# Dependencies for the Serai node
RUN apt install -y make protobuf-compiler

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
  mkdir /serai/bin && \
  cargo build -p serai-coordinator --features parity-db && \
  mv /serai/target/debug/serai-coordinator /serai/bin
FROM debian:bookworm-slim as image

COPY --from=mimalloc libmimalloc.so /usr/lib
RUN echo "/usr/lib/libmimalloc.so" >> /etc/ld.so.preload

RUN apt update && apt upgrade -y && apt autoremove -y && apt clean
# Install ca-certificates
RUN apt install -y ca-certificates

# Switch to a non-root user
RUN useradd --system --create-home --shell /sbin/nologin coordinator
USER coordinator

WORKDIR /home/coordinator

# Copy the Coordinator binary and relevant license
COPY --from=builder --chown=processsor /serai/bin/serai-coordinator /bin/
COPY --from=builder --chown=processsor /serai/AGPL-3.0 .

# Run coordinator
CMD ["serai-coordinator"]
