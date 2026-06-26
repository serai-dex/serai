use std::io;

use blake2::Digest as _;
use chacha20::{
  cipher::{Unsigned as _, IvSizeUser, KeyIvInit as _, StreamCipher as _},
  ChaCha20,
};

use tokio::{
  io::{AsyncReadExt as _, AsyncWriteExt},
  net::TcpStream,
};

pub(super) struct EncryptedSocket {
  socket: TcpStream,
  cipher: ChaCha20,
}

impl EncryptedSocket {
  pub(super) async fn new(mut socket: TcpStream) -> Result<Self, io::Error> {
    let cipher = ChaCha20::new(
      &{
        let our_scalar = curve25519_dalek::Scalar::random(&mut rand_core::OsRng);
        socket
          .write_all(
            (curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE * &our_scalar)
              .compress()
              .as_bytes(),
          )
          .await?;
        socket.flush().await?;
        <_ as AsyncWriteExt>::shutdown(&mut socket).await?;

        let mut their_point = [0; 32];
        socket.read_exact(&mut their_point).await?;
        let their_point = curve25519_dalek::ristretto::CompressedRistretto(their_point)
          .decompress()
          .ok_or(io::Error::other("invalid Ristretto point for ECDH"))?;

        let ecdh = (our_scalar * their_point).compress().to_bytes();
        let shared_secret =
          <[u8; 32]>::from(blake2::Blake2b::<blake2::digest::typenum::U32>::digest(ecdh));

        shared_secret.into()
      },
      &[0; <ChaCha20 as IvSizeUser>::IvSize::USIZE].into(),
    );

    Ok(Self { socket, cipher })
  }

  pub(super) async fn read_all(mut self) -> Result<Vec<u8>, io::Error> {
    let mut result = vec![];
    self.socket.read_to_end(&mut result).await?;
    self.cipher.apply_keystream(&mut result);
    Ok(result)
  }
}
