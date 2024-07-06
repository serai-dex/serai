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
          curve25519_dalek::edwards::CompressedEdwardsY({:?}).decompress().unwrap(),
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

  let path = Path::new(&env::var("OUT_DIR").unwrap()).join(path);
  let _ = remove_file(&path);
  File::create(&path)
    .unwrap()
    .write_all(
      format!(
        "
          static GENERATORS_CELL: OnceLock<Generators> = OnceLock::new();
          pub(crate) fn GENERATORS() -> &'static Generators {{
            GENERATORS_CELL.get_or_init(|| Generators {{
              G: std_shims::vec![
                {G_str}
              ],
              H: std_shims::vec![
                {H_str}
              ],
            }})
          }}
        ",
      )
      .as_bytes(),
    )
    .unwrap();
}

#[cfg(not(feature = "compile-time-generators"))]
fn generators(prefix: &'static str, path: &str) {
  let path = Path::new(&env::var("OUT_DIR").unwrap()).join(path);
  let _ = remove_file(&path);
  File::create(&path)
    .unwrap()
    .write_all(
      format!(
        r#"
        static GENERATORS_CELL: OnceLock<Generators> = OnceLock::new();
        pub(crate) fn GENERATORS() -> &'static Generators {{
          GENERATORS_CELL.get_or_init(|| {{
            monero_generators::bulletproofs_generators(b"{prefix}")
          }})
        }}
      "#,
      )
      .as_bytes(),
    )
    .unwrap();
}

fn main() {
  println!("cargo:rerun-if-changed=build.rs");

  generators("bulletproof", "generators.rs");
  generators("bulletproof_plus", "generators_plus.rs");
}
