#![cfg(feature = "multisig")]

use rand::{RngCore, rngs::OsRng};

use monero_serai::{frost::MultisigError, key_image};

mod frost;
use crate::frost::{THRESHOLD, PARTICIPANTS, generate_keys};

#[test]
fn test() -> Result<(), MultisigError> {
  let (keys, group_private) = generate_keys();
  let image = key_image::generate(&group_private);

  let mut included = (1 ..= PARTICIPANTS).into_iter().collect::<Vec<usize>>();
  while included.len() > THRESHOLD {
    included.swap_remove((OsRng.next_u64() as usize) % included.len());
  }
  included.sort();

  let mut packages = vec![];
  packages.resize(PARTICIPANTS + 1, None);
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
