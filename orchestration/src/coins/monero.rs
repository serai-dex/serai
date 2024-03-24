use std::{path::Path};

use crate::{Network, Os, mimalloc, write_dockerfile};

fn monero_internal(
  network: Network,
  os: Os,
  orchestration_path: &Path,
  folder: &str,
  monero_binary: &str,
  ports: &str,
) {
  const MONERO_VERSION: &str = "0.18.3.1";

  let arch = match std::env::consts::ARCH {
    // We probably would run this without issues yet it's not worth needing to provide support for
    "x86" | "arm" => panic!("unsupported architecture, please download a 64-bit OS"),
    "x86_64" => "x64",
    "aarch64" => "armv8",
    _ => panic!("unsupported architecture"),
  };

  #[rustfmt::skip]
  let download_monero = format!(r#"
FROM alpine:latest as monero

RUN apk --no-cache add gnupg

# Download Monero
RUN wget https://downloads.getmonero.org/cli/monero-linux-{arch}-v{MONERO_VERSION}.tar.bz2

# Verify Binary -- fingerprint from https://github.com/monero-project/monero-site/issues/1949
ADD orchestration/{}/coins/monero/hashes-v{MONERO_VERSION}.txt .
RUN gpg --keyserver hkp://keyserver.ubuntu.com:80 --keyserver-options no-self-sigs-only --receive-keys 81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92 && \
  gpg --verify hashes-v{MONERO_VERSION}.txt && \
  grep "$(sha256sum monero-linux-{arch}-v{MONERO_VERSION}.tar.bz2 | cut -c 1-64)" hashes-v{MONERO_VERSION}.txt

# Extract it
RUN tar -xvjf monero-linux-{arch}-v{MONERO_VERSION}.tar.bz2 --strip-components=1
"#,
    network.label(),
  );

  let setup = mimalloc(os).to_string() + &download_monero;

  let run_monero = format!(
    r#"
COPY --from=monero --chown=monero:nogroup {monero_binary} /bin

EXPOSE {ports}

ADD /orchestration/{}/coins/{folder}/run.sh /
CMD ["/run.sh"]
"#,
    network.label(),
  );

  let run = crate::os(
    os,
    if os == Os::Alpine { "RUN apk --no-cache add gcompat" } else { "" },
    "monero",
  ) + &run_monero;
  let res = setup + &run;

  let mut monero_path = orchestration_path.to_path_buf();
  monero_path.push("coins");
  monero_path.push(folder);
  monero_path.push("Dockerfile");

  write_dockerfile(monero_path, &res);
}

pub fn monero(orchestration_path: &Path, network: Network) {
  monero_internal(
    network,
    if network == Network::Dev { Os::Alpine } else { Os::Debian },
    orchestration_path,
    "monero",
    "monerod",
    "18080 18081",
  )
}

pub fn monero_wallet_rpc(orchestration_path: &Path) {
  monero_internal(
    Network::Dev,
    Os::Debian,
    orchestration_path,
    "monero-wallet-rpc",
    "monero-wallet-rpc",
    "18082",
  )
}
