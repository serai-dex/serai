#[test]
pub fn reproducibly_builds() {
  use std::{path::PathBuf, process::Command};

  use rand_core::{RngCore as _, OsRng};

  const RUNS: usize = 3;

  let mut images = vec![];
  for _ in 0 .. RUNS {
    let mut image = [0; 32];
    OsRng.fill_bytes(&mut image);
    images.push(format!("runtime-{}", hex::encode(image)));
  }

  let path = Command::new("cargo")
    .arg("locate-project")
    .arg("--workspace")
    .arg("--message-format")
    .arg("plain")
    .output()
    .unwrap();
  assert!(path.status.success());
  let mut path = PathBuf::from(String::from_utf8(path.stdout).unwrap().trim());
  assert_eq!(path.file_name().unwrap(), "Cargo.toml");
  assert!(path.pop());

  let mut commands = vec![];
  for image in &images {
    commands.push(
      Command::new("docker")
        .current_dir(&path)
        .arg("build")
        .arg("--quiet")
        .arg("--no-cache")
        .arg("--file=./orchestration/runtime/Dockerfile")
        .arg("--tag")
        .arg(image)
        .arg(".")
        .spawn()
        .unwrap(),
    );
  }

  let mut outputs = vec![];
  for (image, mut command) in images.into_iter().zip(commands) {
    assert!(command.wait().unwrap().success());
    outputs.push(
      Command::new("docker")
        .arg("run")
        .arg("--quiet")
        .arg("--pull")
        .arg("never")
        .arg("--rm")
        .arg(&image)
        .arg("busybox")
        .arg("sha256sum")
        .arg("/serai.wasm")
        .output(),
    );
    // Attempt to clean up the image
    let _ = Command::new("docker").arg("rmi").arg(&image).output();
  }

  let mut expected = None;
  for output in outputs {
    let output = output.unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{stdout}\n{}", String::from_utf8(output.stderr).unwrap());
    if expected.is_none() {
      expected = Some(stdout.clone());
    }
    assert_eq!(expected, Some(stdout));
  }

  let result = expected.unwrap();
  let hash = result.split_whitespace().next().unwrap();
  // Check this appears to be a 32-byte hash (encoded as hex)
  assert_eq!(hash.len(), 64);
  hex::decode(hash).unwrap();
  println!("Hash: {hash}");
}
