use core::fmt::Write;
use std::path::Path;

use zeroize::Zeroizing;
use dalek_ff_group::Ristretto;
use ciphersuite::{group::ff::PrimeField, WrappedGroup};

use crate::{Network, Os, mimalloc, os, build_serai_service, write_dockerfile};

pub fn serai(
  orchestration_path: &Path,
  network: Network,
  serai_key: &Zeroizing<<Ristretto as WrappedGroup>::F>,
) {
  // Always builds in release for performance reasons
  let setup = mimalloc(Os::Debian) + &build_serai_service("", Os::Debian, true, "", "serai-node");

  let env_vars = [("KEY", hex::encode(serai_key.to_repr()))];
  let mut env_vars_str = String::new();
  for (env_var, value) in env_vars {
    write!(&mut env_vars_str, r#"{env_var}=${{{env_var}:="{value}"}} "#).unwrap();
  }

  let run_serai = format!(
    r#"
# Copy the Serai binary and relevant license
COPY --from=builder --chown=serai /serai/bin/serai-node /bin/
COPY --from=builder --chown=serai /serai/AGPL-3.0 .

# Run the Serai node
EXPOSE 30333 9944

ADD /orchestration/{}/serai/run.sh /
CMD {env_vars_str} "/run.sh"
"#,
    network.label(),
  );

  let run = os(Os::Debian, "", "serai") + &run_serai;
  let res = setup + &run;

  let mut serai_path = orchestration_path.to_path_buf();
  serai_path.push("serai");
  serai_path.push("Dockerfile");
  write_dockerfile(serai_path, &res);
}
