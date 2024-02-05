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
FROM alpine:latest as monero

# https://downloads.getmonero.org/cli/monero-linux-x64-v0.18.3.1.tar.bz2
# Verification will fail if MONERO_VERSION doesn't match the latest
# due to the way monero publishes releases. They overwrite a single hashes.txt
# file with each release, meaning we can only grab the SHA256 of the latest
# release.
# Most publish a asc file for each release / build architecture ¯\_(ツ)_/¯
ENV MONERO_VERSION=0.18.3.1

RUN apk --no-cache add gnupg

# Download Monero
RUN wget https://downloads.getmonero.org/cli/monero-linux-x64-v${MONERO_VERSION}.tar.bz2

# Verify Binary -- fingerprint from https://github.com/monero-project/monero-site/issues/1949
ADD ./temp/hashes-v${MONERO_VERSION}.txt .
RUN gpg --keyserver hkp://keyserver.ubuntu.com:80 --keyserver-options no-self-sigs-only --receive-keys 81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92 && \
  gpg --verify hashes-v${MONERO_VERSION}.txt && \
  grep "$(sha256sum monero-linux-x64-v${MONERO_VERSION}.tar.bz2 | cut -c 1-64)" hashes-v${MONERO_VERSION}.txt

# Extract it
RUN tar -xvjf monero-linux-x64-v${MONERO_VERSION}.tar.bz2 --strip-components=1
FROM debian:bookworm-slim as image

COPY --from=mimalloc libmimalloc.so /usr/lib
RUN echo "/usr/lib/libmimalloc.so" >> /etc/ld.so.preload

RUN apt update && apt upgrade -y && apt autoremove -y && apt clean
# Switch to a non-root user
# System user (not a human), shell of nologin, no password assigned
RUN useradd --system --create-home --shell /sbin/nologin monero
USER monero

WORKDIR /home/monero
COPY --from=monero --chown=monero monero-wallet-rpc /bin
ADD scripts /scripts

EXPOSE 6061
