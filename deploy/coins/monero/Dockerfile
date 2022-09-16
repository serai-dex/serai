# Prepare Environment
FROM alpine:latest as builder
# https://downloads.getmonero.org/cli/monero-linux-x64-v0.18.1.0.tar.bz2
# Verification will fail if MONERO_VERSION doesn't match the latest
# due to the way monero publishes releases. They overwrite a single hashes.txt file
# each release, meaning we can only grab the SHA256 of the latest release.
# Most publish a asc file for each release / build architecture ¯\_(ツ)_/¯ 
ENV MONERO_VERSION=0.18.1.0
# monero-linux-x64-v0.18.1.0.tar.bz2 - https://github.com/monero-project/monero-site/commit/9dda1e3ccb84aa14dc09ed598a6d438c18363833
ENV GLIBC_VERSION=2.28-r0

WORKDIR /home/monero

RUN apk update \
	&& apk --no-cache add ca-certificates gnupg bash su-exec

# Get Binary
RUN wget https://downloads.getmonero.org/cli/monero-linux-x64-v${MONERO_VERSION}.tar.bz2

# Verify Binary -- fingerprint from https://github.com/monero-project/monero-site/issues/1949
ENV KEYS F0AF4D462A0BDF92
RUN gpg --keyserver hkp://keyserver.ubuntu.com:80 --keyserver-options no-self-sigs-only --receive-keys ${KEYS}

ADD ./temp/hashes-v${MONERO_VERSION}.txt .
RUN gpg --verify hashes-v${MONERO_VERSION}.txt \
    && cat hashes-v${MONERO_VERSION}.txt | grep "$(sha256sum monero-linux-x64-v${MONERO_VERSION}.tar.bz2 | cut -c 1-64)"

# Cleanup
RUN tar -xvjf monero-linux-x64-v${MONERO_VERSION}.tar.bz2 --strip-components=1

# Prepare Image
FROM ubuntu:latest as image

WORKDIR /home/monero
COPY --from=builder /home/monero/* .
RUN mv * /bin/
COPY ./scripts /scripts

EXPOSE 18080 18081
VOLUME /home/monero/.bitmonero

CMD ["monerod"]
