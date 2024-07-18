use std::path::Path;

use crate::{Network, Os, mimalloc, os, build_serai_service, write_dockerfile};

pub fn ethereum_relayer(orchestration_path: &Path, network: Network) {
  let setup = mimalloc(Os::Debian).to_string() +
    &build_serai_service("", network.release(), network.db(), "serai-ethereum-relayer");

  let env_vars = [
    ("DB_PATH", "/volume/ethereum-relayer-db".to_string()),
    ("RUST_LOG", "info,serai_ethereum_relayer=trace".to_string()),
  ];
  let mut env_vars_str = String::new();
  for (env_var, value) in env_vars {
    env_vars_str += &format!(r#"{env_var}=${{{env_var}:="{value}"}} "#);
  }

  let run_ethereum_relayer = format!(
    r#"
# Copy the relayer server binary and relevant license
COPY --from=builder --chown=ethereumrelayer /serai/bin/serai-ethereum-relayer /bin

# Run ethereum-relayer
EXPOSE 20830
EXPOSE 20831
CMD {env_vars_str} serai-ethereum-relayer
"#
  );

  let run = os(Os::Debian, "", "ethereumrelayer") + &run_ethereum_relayer;
  let res = setup + &run;

  let mut ethereum_relayer_path = orchestration_path.to_path_buf();
  ethereum_relayer_path.push("networks");
  ethereum_relayer_path.push("ethereum-relayer");
  ethereum_relayer_path.push("Dockerfile");

  write_dockerfile(ethereum_relayer_path, &res);
}
