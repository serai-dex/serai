fn main() {
  println!("cargo::rustc-check-cfg=cfg(zalloc_rustc_nightly)");

  #[expect(clippy::disallowed_methods)]
  let rustc = std::env::var("RUSTC")
    .expect("`cargo` didn't set the `RUSTC` environment variable for a build script?");
  let version =
    std::process::Command::new(rustc).arg("--version").output().expect("failed to invoke `rustc`");
  assert!(version.status.success(), "`rustc` errored when fetching the version information");
  let version =
    String::from_utf8(version.stdout).expect("`rustc` version information wasn't UTF-8");
  /*
    This is a naive check but should be sufficient as misconfiguration would simoply cause a build
    failure.
  */
  if version.contains("nightly") {
    println!("cargo::rustc-cfg=zalloc_rustc_nightly");
  }
}
