# Configure Environment
FROM alpine:latest as builder

ENV BITCOIN_VERSION=23.0
ENV GLIBC_VERSION=2.28-r0
ENV BITCOIN_DATA=/home/bitcoin/.bitcoin

WORKDIR /home/bitcoin


RUN apk update \
	&& apk --no-cache add ca-certificates gnupg bash su-exec 

# Get Binary
# TODO: When bitcoin.org publishes 23.0, retrieve checksums from there.
RUN wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz \
	&& wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS \
	&& wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS.asc

# Verify Binary
# For the PGP keys of builders and developers, refer to 
# https://github.com/bitcoin/bitcoin/tree/master/contrib/builder-keys
# Serai recognizes the builder keys for 16/17 signatures
# from the 23.0 release
ENV KEYS 152812300785C96444D3334D17565732E08E5E41 0AD83877C1F0CD1EE9BD660AD7CC770B81FD22A8 590B7292695AFFA5B672CBB2E13FC145CD3F4304 948444FCE03B05BA5AB0591EC37B1C1D44C786EE 9EDAFF80E080659604F4A76B2EBB056FD847F8A7 E777299FC265DD04793070EB944D35F9AC3DB76A F4FC70F07310028424EFC20A8E4256593F177720 D1DBF2C4B96F2DEBF4C16654410108112E7EA81F
ENV KEYS2 4DAF18FE948E7A965B30F9457E296D555E7F63A7 28E72909F1717FE9607754F8A7BEB2621678D37D 74E2DEF5D77260B98BC19438099BAD163C70FBFA 71A3B16735405025D447E8F274810B012346C9A6 E463A93F5F3117EEDE6C7316BD02942421F4889F 9D3CC86A72F8494342EA5FD10A41BDC3F4FAFF1C 287AE4CA1187C68C08B49CB2D11BD4F33F1DB499 F9A8737BF4FF5C89C903DF31DD78544CF91B1514

# Use hardcoded prints to get keys from servers. 2 Different servers used.
RUN gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys ${KEYS} \
	&& gpg --keyserver hkp://keys.openpgp.org:80 --recv-keys ${KEYS2}

# verify all sigs and check for valid signature from laanwj -- 71A3
RUN gpg --verify --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS | grep "^\[GNUPG:\] VALIDSIG.*71A3B16735405025D447E8F274810B012346C9A6" 

RUN grep bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz SHA256SUMS | sha256sum -c

# Prepare Image
RUN tar xzvf bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz

# Prepare Image
FROM ubuntu:latest as image
WORKDIR /home/bitcoin
COPY --from=builder /home/bitcoin/* .

RUN mv bin/* /bin \
&& mv lib/* /lib \
&& mv share/* /share

COPY ./scripts /scripts

EXPOSE 8332 8333 18332 18333 18443 18444
VOLUME ["/home/bitcoin/.bitcoin"]

# Run
CMD ["bitcoind"]
