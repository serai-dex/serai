use std::path::Path;

use crate::{Network, Os, mimalloc, os, write_dockerfile};

pub fn bitcoin(orchestration_path: &Path, network: Network) {
  const VERSION: &str = "30.0";
  let file = format!("bitcoin-{VERSION}-$(uname -m)-linux-gnu.tar.gz");
  let url = format!("https://bitcoincore.org/bin/bitcoin-core-{VERSION}");

  #[rustfmt::skip]
  let download_bitcoin = format!(r#"
FROM alpine:latest AS bitcoin

RUN apk --no-cache add git gnupg

# Download Bitcoin
RUN wget {url}/{file}
RUN wget {url}/SHA256SUMS
RUN wget {url}/SHA256SUMS.asc

# Verify all sigs and check for a valid signature from laanwj -- 71A3
RUN git clone https://github.com/bitcoin-core/guix.sigs && \
  cd guix.sigs/builder-keys && \
  find . -name '*.gpg' -exec gpg --import {{}} \; && \
  gpg --verify --status-fd 1 --verify ../../SHA256SUMS.asc ../../SHA256SUMS | grep "^\[GNUPG:\] VALIDSIG.*71A3B16735405025D447E8F274810B012346C9A6"

RUN grep "{file}" SHA256SUMS | sha256sum -c

RUN tar -xf "{file}"
RUN mv $(find . -name bitcoind) .
"#);

  let setup = mimalloc(Os::Alpine) + &download_bitcoin;

  let run_bitcoin = format!(
    r#"
COPY --from=bitcoin --chown=bitcoin bitcoind /bin

EXPOSE 8332 8333

ADD /orchestration/{}/networks/bitcoin/run.sh /
CMD ["/run.sh"]
"#,
    network.label()
  );

  let run = os(Os::Alpine, "", "bitcoin") + &run_bitcoin;
  let res = setup + &run;

  let mut bitcoin_path = orchestration_path.to_path_buf();
  bitcoin_path.extend(["networks", "bitcoin", "Dockerfile"]);
  write_dockerfile(bitcoin_path, &res);
}
