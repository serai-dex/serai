use std::{path::Path};

use crate::{Os, mimalloc, os, write_dockerfile};

#[rustfmt::skip]
pub fn bitcoin(orchestration_path: &Path) {
  const DOWNLOAD_BITCOIN: &str = r#"
FROM alpine:latest as bitcoin

ENV BITCOIN_VERSION=26.0

RUN apk --no-cache add git gnupg

# Download Bitcoin
RUN wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-$(uname -m)-linux-gnu.tar.gz \
  && wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS \
  && wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS.asc

# Verify all sigs and check for a valid signature from laanwj -- 71A3
RUN git clone https://github.com/bitcoin-core/guix.sigs && \
  cd guix.sigs/builder-keys && \
  find . -iname '*.gpg' -exec gpg --import {} \; && \
  gpg --verify --status-fd 1 --verify ../../SHA256SUMS.asc ../../SHA256SUMS | grep "^\[GNUPG:\] VALIDSIG.*71A3B16735405025D447E8F274810B012346C9A6"

RUN grep bitcoin-${BITCOIN_VERSION}-$(uname -m)-linux-gnu.tar.gz SHA256SUMS | sha256sum -c

# Prepare Image
RUN tar xzvf bitcoin-${BITCOIN_VERSION}-$(uname -m)-linux-gnu.tar.gz
RUN mv bitcoin-${BITCOIN_VERSION}/bin/bitcoind .
"#;

  let setup = mimalloc(Os::Debian).to_string() + DOWNLOAD_BITCOIN;

  const RUN_BITCOIN: &str = r#"
COPY --from=bitcoin --chown=bitcoin bitcoind /bin

EXPOSE 8332 8333

ADD /orchestration/coins/bitcoin/scripts /scripts
CMD ["/scripts/entry-dev.sh"]
"#;

  let run = os(Os::Debian, "", "bitcoin") + RUN_BITCOIN;
  let res = setup + &run;

  let mut bitcoin_path = orchestration_path.to_path_buf();
  bitcoin_path.push("coins");
  bitcoin_path.push("bitcoin");
  bitcoin_path.push("Dockerfile");

  write_dockerfile(bitcoin_path, &res);
}
