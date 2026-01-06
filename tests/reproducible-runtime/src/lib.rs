#![cfg_attr(test, expect(unexpected_cfgs))]

#[test]
pub fn reproducibly_builds() {
  use std::{path::PathBuf, process::Command};

  use rand_core::{RngCore as _, OsRng};

  const RUNS: usize = {
    // 3 is a sane, healthy amount of runs to ensure this isn't being randomized when built.
    #[cfg(any(target_arch = "x86_64", not(github_ci)))]
    let runs = 3;
    // This test is _incredibly_ slow when the host has to be emulated, so when in the GitHub CI
    // where this will be cross-checked against other machines, we only run it once.
    #[cfg(all(not(target_arch = "x86_64"), github_ci))]
    let runs = 1;
    runs
  };

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

  {
    // Build the images in parallel
    let mut commands = vec![];
    for image in &images {
      #[cfg_attr(not(github_ci), expect(unused_mut))]
      let mut command = Command::new("docker")
        .current_dir(&path)
        .arg("build")
        .arg("--quiet")
        .arg("--no-cache")
        .arg("--file=./orchestration/runtime/Dockerfile")
        .arg("--tag")
        .arg(image)
        .arg(".")
        .spawn()
        .unwrap();

      // In the GH CI, we force this to be sequential due to experiencing OOM kills on
      // `macos-15-intel`. This doesn't take so long to run we're concerned about any time limit.
      #[cfg(github_ci)]
      assert!(command.wait().unwrap().success());

      commands.push(command);
    }

    // Join all of the commands
    for mut command in commands {
      assert!(command.wait().unwrap().success());
    }
  }

  let mut outputs = vec![];
  for image in images {
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
