use blake2::{Digest, Blake2s256};

pub(crate) fn merkle(hash_args: &[[u8; 32]]) -> [u8; 32] {
  let mut hashes = Vec::with_capacity(hash_args.len());
  for hash in hash_args {
    hashes.push(Blake2s256::digest([b"leaf_hash".as_ref(), hash].concat()));
  }

  let zero = [0; 32];
  let mut interim;
  while hashes.len() > 1 {
    interim = Vec::with_capacity((hashes.len() + 1) / 2);

    let mut i = 0;
    while i < hashes.len() {
      interim.push(Blake2s256::digest(
        [
          b"branch_hash".as_ref(),
          hashes[i].as_ref(),
          hashes.get(i + 1).map_or(zero.as_ref(), AsRef::as_ref),
        ]
        .concat(),
      ));
      i += 2;
    }

    hashes = interim;
  }

  hashes.first().copied().map_or(zero, Into::into)
}
