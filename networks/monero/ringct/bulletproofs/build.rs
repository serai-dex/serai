use std::{
  io::Write,
  env,
  path::Path,
  fs::{File, remove_file},
};

#[cfg(feature = "compile-time-generators")]
fn generators(prefix: &'static str, path: &str) {
  use curve25519_dalek::EdwardsPoint;

  use monero_generators::bulletproofs_generators;

  fn serialize(generators_string: &mut String, points: &[EdwardsPoint]) {
    for generator in points {
      generators_string.extend(
        format!(
          "
          curve25519_dalek::edwards::CompressedEdwardsY({:?})
            .decompress()
            .expect(\"generator from build script wasn't on-curve\"),
          ",
          generator.compress().to_bytes()
        )
        .chars(),
      );
    }
  }

  let generators = bulletproofs_generators(prefix.as_bytes());
  #[allow(non_snake_case)]
  let mut G_str = String::new();
  serialize(&mut G_str, &generators.G);
  #[allow(non_snake_case)]
  let mut H_str = String::new();
  serialize(&mut H_str, &generators.H);

  let path = Path::new(&env::var("OUT_DIR").expect("cargo didn't set $OUT_DIR")).join(path);
  let _ = remove_file(&path);
  File::create(&path)
    .expect("failed to create file in $OUT_DIR")
    .write_all(
      format!(
        "
          pub(crate) static GENERATORS: LazyLock<Generators> = LazyLock::new(|| Generators {{
            G: std_shims::vec![
              {G_str}
            ],
            H: std_shims::vec![
              {H_str}
            ],
          }});
        ",
      )
      .as_bytes(),
    )
    .expect("couldn't write generated source code to file on disk");
}

#[cfg(not(feature = "compile-time-generators"))]
fn generators(prefix: &'static str, path: &str) {
  let path = Path::new(&env::var("OUT_DIR").expect("cargo didn't set $OUT_DIR")).join(path);
  let _ = remove_file(&path);
  File::create(&path)
    .expect("failed to create file in $OUT_DIR")
    .write_all(
      format!(
        r#"
        pub(crate) static GENERATORS: LazyLock<Generators> = LazyLock::new(|| {{
          monero_generators::bulletproofs_generators(b"{prefix}")
        }});
      "#,
      )
      .as_bytes(),
    )
    .expect("couldn't write generated source code to file on disk");
}

fn main() {
  println!("cargo:rerun-if-changed=build.rs");

  generators("bulletproof", "generators.rs");
  generators("bulletproof_plus", "generators_plus.rs");
}
