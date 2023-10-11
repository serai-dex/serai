FROM alpine:latest as builder

# https://downloads.getmonero.org/cli/monero-linux-x64-v0.18.3.1.tar.bz2
# Verification will fail if MONERO_VERSION doesn't match the latest
# due to the way monero publishes releases. They overwrite a single hashes.txt
# file with each release, meaning we can only grab the SHA256 of the latest
# release.
# Most publish a asc file for each release / build architecture ¯\_(ツ)_/¯
ENV MONERO_VERSION=0.18.3.1

WORKDIR /home/monero

RUN apk update && apk --no-cache add gcc g++ libc-dev make cmake git
RUN git clone https://github.com/microsoft/mimalloc && \
  cd mimalloc && \
  mkdir -p out/secure && \
  cd out/secure && \
  cmake -DMI_SECURE=ON ../.. && \
  make && \
  cp ./libmimalloc-secure.so ../../../libmimalloc.so

RUN apk --no-cache add gnupg

# Download Monero
RUN wget https://downloads.getmonero.org/cli/monero-linux-x64-v${MONERO_VERSION}.tar.bz2

# Verify Binary -- fingerprint from https://github.com/monero-project/monero-site/issues/1949
ADD ./temp/hashes-v${MONERO_VERSION}.txt .
RUN gpg --keyserver hkp://keyserver.ubuntu.com:80 --keyserver-options no-self-sigs-only --receive-keys 81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92 && \
  gpg --verify hashes-v${MONERO_VERSION}.txt && \
  grep "$(sha256sum monero-linux-x64-v${MONERO_VERSION}.tar.bz2 | cut -c 1-64)" hashes-v${MONERO_VERSION}.txt

# Cleanup
RUN tar -xvjf monero-linux-x64-v${MONERO_VERSION}.tar.bz2 --strip-components=1

# Build the actual image
FROM alpine:latest as image

COPY --from=builder /home/monero/libmimalloc.so /usr/lib
ENV LD_PRELOAD=libmimalloc.so

# Upgrade packages
RUN apk update && apk upgrade && apk --no-cache add gcompat

# Switch to a non-root user
# System user (not a human), shell of nologin, no password assigned
RUN adduser -S -s /sbin/nologin -D monero
USER monero

WORKDIR /home/monero
COPY --from=builder --chown=monero /home/monero/monerod /bin
ADD scripts /scripts

EXPOSE 18080 18081
# VOLUME /home/monero/.bitmonero
