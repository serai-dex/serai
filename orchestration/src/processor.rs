use std::{path::Path};

use crate::{Os, mimalloc, os, build_serai_service, write_dockerfile};

pub fn processor(orchestration_path: &Path, coin: &'static str) {
  let setup = mimalloc(Os::Debian).to_string() +
    &build_serai_service(false, &format!("binaries parity-db {coin}"), "serai-processor");

  const ADDITIONAL_ROOT: &str = r#"
# Install ca-certificates
RUN apt install -y ca-certificates
"#;

  const RUN_PROCESSOR: &str = r#"
# Copy the Processor binary and relevant license
COPY --from=builder --chown=processor /serai/bin/serai-processor /bin/
COPY --from=builder --chown=processor /serai/AGPL-3.0 .

# Run processor
CMD ["serai-processor"]
"#;

  let run = os(Os::Debian, ADDITIONAL_ROOT, "processor") + RUN_PROCESSOR;
  let res = setup + &run;

  let mut processor_path = orchestration_path.to_path_buf();
  processor_path.push("processor");
  processor_path.push(coin);
  processor_path.push("Dockerfile");

  write_dockerfile(processor_path, &res);
}
