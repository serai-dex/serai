use std::path::Path;

use crate::{Network, Os, mimalloc, os, write_dockerfile};

mod execution;
use execution::*;

mod consensus;
use consensus::*;

pub fn ethereum(orchestration_path: &Path, network: Network) {
  let ((el_download, el_run_as_root, el_run), (cl_download, cl_run_as_root, cl_run)) =
    if network == Network::Dev {
      (anvil(network), (String::new(), String::new(), String::new()))
    } else {
      // TODO: Select an EL/CL based off a RNG seeded from the public key
      (reth(network), nimbus(network))
    };

  let download = mimalloc(Os::Alpine).to_string() + &el_download + &cl_download;

  let run = format!(
    r#"
ADD /orchestration/{}/coins/ethereum/run.sh /run.sh
CMD ["/run.sh"]
"#,
    network.label()
  );
  let run = mimalloc(Os::Debian).to_string() +
    &os(Os::Debian, &(el_run_as_root + "\r\n" + &cl_run_as_root), "ethereum") +
    &el_run +
    &cl_run +
    &run;

  let res = download + &run;

  let mut ethereum_path = orchestration_path.to_path_buf();
  ethereum_path.push("coins");
  ethereum_path.push("ethereum");
  ethereum_path.push("Dockerfile");

  write_dockerfile(ethereum_path, &res);
}
