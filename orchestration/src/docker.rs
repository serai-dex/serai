use std::{collections::HashSet, path::Path, env, process::Command};

use crate::Network;

pub fn build(orchestration_path: &Path, network: Network, name: &str) {
  let mut repo_path = env::current_exe().unwrap();
  repo_path.pop();
  if repo_path.as_path().ends_with("deps") {
    repo_path.pop();
  }
  assert!(repo_path.as_path().ends_with("debug") || repo_path.as_path().ends_with("release"));
  repo_path.pop();
  assert!(repo_path.as_path().ends_with("target"));
  repo_path.pop();

  let mut dockerfile_path = orchestration_path.to_path_buf();
  if HashSet::from(["bitcoin", "ethereum", "monero", "monero-wallet-rpc"]).contains(name) {
    dockerfile_path = dockerfile_path.join("networks");
  }
  if name.contains("-processor") {
    dockerfile_path =
      dockerfile_path.join("processor").join(name.split('-').next().unwrap()).join("Dockerfile");
  } else {
    dockerfile_path = dockerfile_path.join(name).join("Dockerfile");
  }

  println!("Building {}...", &name);

  if !Command::new("docker")
    .current_dir(&repo_path)
    .arg("build")
    .arg("-f")
    .arg(dockerfile_path)
    .arg(".")
    .arg("-t")
    .arg(format!("serai-{}-{name}-img", network.label()))
    .spawn()
    .unwrap()
    .wait()
    .unwrap()
    .success()
  {
    panic!("failed to build {name}");
  }

  println!("Built!");
}
