#[rustversion::nightly]
fn main() {
  println!("cargo::rustc-check-cfg=cfg(zalloc_rustc_nightly)");
  println!("cargo::rustc-cfg=zalloc_rustc_nightly");
}

#[rustversion::not(nightly)]
fn main() {
  println!("cargo::rustc-check-cfg=cfg(zalloc_rustc_nightly)");
}
