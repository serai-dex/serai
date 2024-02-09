use std::{path::Path};

use zeroize::Zeroizing;

use ciphersuite::{group::ff::PrimeField, Ciphersuite, Ristretto};

use crate::{Network, Os, mimalloc, os, build_serai_service, write_dockerfile};

#[allow(clippy::needless_pass_by_value)]
pub fn coordinator(
  orchestration_path: &Path,
  network: Network,
  coordinator_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
) {
  let db = network.db();
  let os_to_use = if db == "parity-db" { Os::Alpine } else { Os::Debian };
  let longer_reattempts = if network == Network::Dev { "longer-reattempts" } else { "" };
  let setup = mimalloc(os_to_use).to_string() +
    &build_serai_service(
      os_to_use,
      network.release(),
      &format!("{db} {longer_reattempts}"),
      "serai-coordinator",
    );

  let additional_root = if os_to_use == Os::Alpine {
    r#"
# Install ca-certificates
RUN apk add ca-certificates
"#
  } else {
    r#"
# Install ca-certificates
RUN apt install -y ca-certificates
"#
  };

  let env_vars = [
    ("MESSAGE_QUEUE_RPC", format!("serai-{}-message-queue", network.label())),
    ("MESSAGE_QUEUE_KEY", hex::encode(coordinator_key.to_repr())),
    ("DB_PATH", "./coordinator-db".to_string()),
    ("SERAI_KEY", hex::encode(serai_key.to_repr())),
    ("SERAI_HOSTNAME", format!("serai-{}-serai", network.label())),
    ("RUST_LOG", "serai_coordinator=debug,tributary_chain=debug,tendermint=debug".to_string()),
  ];
  let mut env_vars_str = String::new();
  for (env_var, value) in env_vars {
    env_vars_str += &format!(r#"{env_var}=${{{env_var}:="{value}"}} "#);
  }

  let run_coordinator = format!(
    r#"
# Copy the Coordinator binary and relevant license
COPY --from=builder --chown=coordinator /serai/bin/serai-coordinator /bin/
COPY --from=builder --chown=coordinator /serai/AGPL-3.0 .

# Run coordinator
CMD {env_vars_str} serai-coordinator
"#
  );

  let run = os(os_to_use, additional_root, "coordinator") + &run_coordinator;
  let res = setup + &run;

  let mut coordinator_path = orchestration_path.to_path_buf();
  coordinator_path.push("coordinator");
  coordinator_path.push("Dockerfile");

  write_dockerfile(coordinator_path, &res);
}
