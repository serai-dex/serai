#![cfg(feature = "multisig")]

use rand::{RngCore, rngs::OsRng};

use curve25519_dalek::{traits::Identity, edwards::EdwardsPoint};

use monero_serai::key_image;

mod frost;
use crate::frost::{THRESHOLD, PARTICIPANTS, generate_keys};

#[test]
fn test() {
  let (keys, group_private) = generate_keys();
  let image = key_image::generate(&group_private);

  let mut included = (1 ..= PARTICIPANTS).into_iter().collect::<Vec<usize>>();
  while included.len() > THRESHOLD {
    included.swap_remove((OsRng.next_u64() as usize) % included.len());
  }
  included.sort();

  let mut views = vec![];
  let mut shares = vec![];
  for i in 1 ..= PARTICIPANTS {
    if included.contains(&i) {
      // If they were included, include their view
      views.push(keys[i - 1].view(&included).unwrap());
      let share = key_image::generate_share(&mut OsRng, &views[i - 1]);
      let mut serialized = share.0.compress().to_bytes().to_vec();
      serialized.extend(b"abc");
      serialized.extend(&share.1);
      shares.push(serialized);
    } else {
      // If they weren't included, include dummy data to fill the Vec
      // Uses the view of someone actually included as Params::new verifies inclusion
      views.push(keys[included[0] - 1].view(&included).unwrap());
      shares.push(vec![]);
    }
  }

  for i in &included {
    let mut multi_image = EdwardsPoint::identity();
    for l in &included {
      let share = key_image::verify_share(&views[i - 1], *l, &shares[l - 1]).unwrap();
      assert_eq!(share.1, b"abc");
      multi_image += share.0;
    }
    assert_eq!(image, multi_image);
  }
}
