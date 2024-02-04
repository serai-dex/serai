use std::{path::Path, io::Write, fs::File};

use crate::{Os, mimalloc, os, build_serai_service};

pub fn serai(orchestration_path: &Path) {
  let setup = mimalloc(Os::Debian).to_string() + &build_serai_service(true, "", "serai-node");

  const RUN_SERAI: &str = r#"
# Copy the Serai binary and relevant license
COPY --from=builder --chown=serai /serai/bin/serai-node /bin/
COPY --from=builder --chown=serai /serai/AGPL-3.0 .

# Run the Serai node
EXPOSE 30333 9615 9933 9944
CMD ["serai-node"]
"#;

  let run = os(Os::Debian, "", "serai") + RUN_SERAI;
  let res = setup + &run;

  let mut serai_path = orchestration_path.to_path_buf();
  serai_path.push("serai");
  serai_path.push("Dockerfile");

  File::create(serai_path).unwrap().write_all(res.as_bytes()).unwrap();
}
