fn main() {
  println!("cargo:rerun-if-changed=contracts");
  println!("cargo:rerun-if-changed=artifacts");
  println!("cargo:rerun-if-changed=foundry.toml");

  assert!(std::process::Command::new("forge").args(["build"]).status().unwrap().success());
}
