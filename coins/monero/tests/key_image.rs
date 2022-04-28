#![cfg(feature = "multisig")]

use rand::rngs::OsRng;

use monero_serai::{SignError, key_image};

mod frost;
use crate::frost::generate_keys;

#[test]
fn test() -> Result<(), SignError> {
  let (keys, group_private) = generate_keys(3, 5);
  let image = key_image::generate(&group_private);

  let mut packages = vec![];
  packages.resize(5 + 1, None);
  let included = vec![1, 3, 4];
  for i in &included {
    let i = *i;
    packages[i] = Some(
      (
        keys[0].verification_shares()[i].0,
        key_image::multisig(&mut OsRng, &keys[i - 1], &included)
      )
    );
  }

  for i in included {
    let mut packages = packages.clone();
    packages.push(None);
    let package = packages.swap_remove(i).unwrap().1;
    assert_eq!(image, package.resolve(packages).unwrap());
  }

  Ok(())
}
