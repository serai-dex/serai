use std::{path::Path};

use crate::{Network, Os, mimalloc, os, build_serai_service, write_dockerfile};

pub fn processor(orchestration_path: &Path, network: Network, coin: &'static str) {
  let setup = mimalloc(Os::Debian).to_string() +
    &build_serai_service(
      network.release(),
      &format!("binaries {} {coin}", network.db()),
      "serai-processor",
    );

  const ADDITIONAL_ROOT: &str = r#"
# Install ca-certificates
RUN apt install -y ca-certificates
"#;

  let env_vars = [
    ("MESSAGE_QUEUE_KEY", ""),
    ("ENTROPY", ""),
    ("NETWORK", ""),
    ("NETWORK_RPC_LOGIN", ""),
    ("NETWORK_RPC_PORT", ""),
    ("DB_PATH", "./processor-db"),
    ("RUST_LOG", "serai_processor=debug"),
  ];
  let mut env_vars_str = String::new();
  for (env_var, value) in env_vars {
    env_vars_str += &format!(r#"{env_var}="${{{env_var}:='{value}'}}" "#);
  }

  let run_processor = format!(
    r#"
# Copy the Processor binary and relevant license
COPY --from=builder --chown=processor /serai/bin/serai-processor /bin/
COPY --from=builder --chown=processor /serai/AGPL-3.0 .

# Run processor
CMD {env_vars_str} serai-processor
"#
  );

  let run = os(Os::Debian, ADDITIONAL_ROOT, "processor") + &run_processor;
  let res = setup + &run;

  let mut processor_path = orchestration_path.to_path_buf();
  processor_path.push("processor");
  processor_path.push(coin);
  processor_path.push("Dockerfile");

  write_dockerfile(processor_path, &res);
}
