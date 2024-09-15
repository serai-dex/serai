#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::{path::PathBuf, fs, process::Command};

/// Build contracts placed in `contracts/`, outputting to `artifacts/`.
///
/// Requires solc 0.8.25.
pub fn build(contracts_path: &str, artifacts_path: &str) -> Result<(), String> {
  println!("cargo:rerun-if-changed={contracts_path}/*");
  println!("cargo:rerun-if-changed={artifacts_path}/*");

  for line in String::from_utf8(
    Command::new("solc")
      .args(["--version"])
      .output()
      .map_err(|_| "couldn't fetch solc output".to_string())?
      .stdout,
  )
  .map_err(|_| "solc stdout wasn't UTF-8")?
  .lines()
  {
    if let Some(version) = line.strip_prefix("Version: ") {
      let version =
        version.split('+').next().ok_or_else(|| "no value present on line".to_string())?;
      if version != "0.8.25" {
        Err(format!("version was {version}, 0.8.25 required"))?
      }
    }
  }

  #[rustfmt::skip]
  let args = [
    "--base-path", ".",
    "-o", "./artifacts", "--overwrite",
    "--bin", "--abi",
    "--via-ir", "--optimize",
    "--no-color",
  ];
  let mut args = args.into_iter().map(str::to_string).collect::<Vec<_>>();

  let mut queue = vec![PathBuf::from(contracts_path)];
  while let Some(folder) = queue.pop() {
    for entry in fs::read_dir(folder).map_err(|e| format!("couldn't read directory: {e:?}"))? {
      let entry = entry.map_err(|e| format!("couldn't read directory in entry: {e:?}"))?;
      let kind = entry.file_type().map_err(|e| format!("couldn't fetch file type: {e:?}"))?;
      if kind.is_dir() {
        queue.push(entry.path());
      }

      if kind.is_file() &&
        entry
          .file_name()
          .into_string()
          .map_err(|_| "file name wasn't a valid UTF-8 string".to_string())?
          .ends_with(".sol")
      {
        args.push(
          entry
            .path()
            .into_os_string()
            .into_string()
            .map_err(|_| "file path wasn't a valid UTF-8 string".to_string())?,
        );
      }

      // We on purposely ignore symlinks to avoid recursive structures
    }
  }

  let solc = Command::new("solc")
    .args(args)
    .output()
    .map_err(|_| "couldn't fetch solc output".to_string())?;
  let stderr =
    String::from_utf8(solc.stderr).map_err(|_| "solc stderr wasn't UTF-8".to_string())?;
  if !solc.status.success() {
    Err(format!("solc didn't successfully execute: {stderr}"))?;
  }
  for line in stderr.lines() {
    if line.contains("Error:") {
      Err(format!("solc output had error: {stderr}"))?;
    }
  }

  Ok(())
}
