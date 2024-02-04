use std::{path::Path};

use crate::{Os, mimalloc, write_dockerfile};

#[rustfmt::skip]
fn monero_internal(os: Os, orchestration_path: &Path, folder: &str, monero_binary: &str, ports: &str) {
  const DOWNLOAD_MONERO: &str = r#"
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
"#;

  let setup = mimalloc(os).to_string() + DOWNLOAD_MONERO;

  let run_monero = format!(r#"
COPY --from=monero --chown=monero {monero_binary} /bin

EXPOSE {ports}

ADD scripts /scripts
CMD ["/scripts/entry-dev.sh"]
"#);

  let run = crate::os(
    os,
    if os == Os::Alpine { "RUN apk --no-cache add gcompat" } else { "" },
    "monero"
  ) + &run_monero;
  let res = setup + &run;

  let mut monero_path = orchestration_path.to_path_buf();
  monero_path.push("coins");
  monero_path.push(folder);
  monero_path.push("Dockerfile");

  write_dockerfile(monero_path, &res);
}

pub fn monero(orchestration_path: &Path) {
  monero_internal(Os::Alpine, orchestration_path, "monero", "monerod", "18080 18081")
}

pub fn monero_wallet_rpc(orchestration_path: &Path) {
  monero_internal(Os::Debian, orchestration_path, "monero-wallet-rpc", "monero-wallet-rpc", "18082")
}
