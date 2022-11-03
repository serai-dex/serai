use aes::Aes128;
use aes::cipher::{BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};

pub fn start() {
  let key = GenericArray::from([0u8; 16]);
  let mut block = GenericArray::from([42u8; 16]);

  // Initialize cipher
  let cipher = Aes128::new(&key);

  let block_copy = block.clone();

  // Encrypt block in-place
  cipher.encrypt_block(&mut block);

  // And decrypt it back
  cipher.decrypt_block(&mut block);
  assert_eq!(block, block_copy);

  // implementation supports parallel block processing
  // number of blocks processed in parallel depends in general
  // on hardware capabilities
  let mut blocks = [block; 100];
  cipher.encrypt_blocks(&mut blocks);

  for block in blocks.iter_mut() {
    cipher.decrypt_block(block);
    assert_eq!(block, &block_copy);
  }

  cipher.decrypt_blocks(&mut blocks);

  for block in blocks.iter_mut() {
    cipher.encrypt_block(block);
    assert_eq!(block, &block_copy);
  }
}
