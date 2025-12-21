use core::fmt::Write as _;
use std::path::Path;

use crate::{Network, Os, mimalloc, write_dockerfile};

pub fn monero(orchestration_path: &Path, network: Network) {
  let os = Os::Alpine;

  const MONERO_VERSION: &str = "0.18.4.4";

  let arch = match std::env::consts::ARCH {
    // We probably would run this without issues yet it's not worth needing to provide support for
    "x86" | "arm" => panic!("unsupported architecture, please download a 64-bit OS"),
    "x86_64" => "x64",
    "aarch64" => "armv8",
    _ => panic!("unsupported architecture"),
  };

  let file = format!("monero-linux-{arch}-v{MONERO_VERSION}.tar.bz2");

  #[rustfmt::skip]
  let mut download_monero = format!(r#"
FROM alpine:latest AS monero

RUN apk --no-cache add gnupg

# Download Monero
RUN wget https://downloads.getmonero.org/cli/{file}

# Verify Binary -- fingerprint from https://github.com/monero-project/monero-site/issues/1949
ADD orchestration/{}/networks/monero/hashes-v{MONERO_VERSION}.txt .
RUN gpg --keyserver hkp://keyserver.ubuntu.com:80 --keyserver-options no-self-sigs-only --receive-keys 81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92 && \
  gpg --verify hashes-v{MONERO_VERSION}.txt && \
  grep "{file}" hashes-v{MONERO_VERSION}.txt | sha256sum -c

# Extract it
RUN tar -xf {file} --strip-components=1
"#,
    network.label(),
  );

  if os == Os::Alpine {
    // Increase the default stack size, as Monero does heavily use its stack
    write!(
      &mut download_monero,
      r#"
ADD orchestration/increase_default_stack_size.sh .
RUN ./increase_default_stack_size.sh monerod
"#
    )
    .unwrap();
  }

  let setup = mimalloc(os) + &download_monero;

  let run_monero = format!(
    r#"
COPY --from=monero --chown=monero:nogroup monerod /bin

EXPOSE 18080 18081

ADD /orchestration/{}/networks/monero/run.sh /
CMD ["/run.sh"]
"#,
    network.label(),
  );

  let run =
    crate::os(os, if os == Os::Alpine { "RUN apk --no-cache add gcompat" } else { "" }, "monero") +
      &run_monero;
  let res = setup + &run;

  let mut monero_path = orchestration_path.to_path_buf();
  monero_path.extend(["networks", "monero", "Dockerfile"]);
  write_dockerfile(monero_path, &res);
}
