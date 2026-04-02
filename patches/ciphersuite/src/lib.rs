#![no_std]

use std_shims::io;

use zeroize::Zeroize;
pub use ciphersuite::group;
use group::{*, ff::*, prime::PrimeGroup};

pub trait Ciphersuite: 'static + Send + Sync {
  type F: PrimeField + PrimeFieldBits + Zeroize;
  type G: Group<Scalar = Self::F> + GroupOps + PrimeGroup + Zeroize;
  #[cfg(feature = "alloc")]
  #[expect(non_snake_case)]
  fn read_F<R: io::Read>(reader: &mut R) -> io::Result<Self::F>;
  #[cfg(feature = "alloc")]
  #[expect(non_snake_case)]
  fn read_G<R: io::Read>(reader: &mut R) -> io::Result<Self::G>;
}
impl<C: ciphersuite::GroupIo> Ciphersuite for C {
  type F = <C as ciphersuite::WrappedGroup>::F;
  type G = <C as ciphersuite::WrappedGroup>::G;
  #[cfg(feature = "alloc")]
  fn read_F<R: io::Read>(reader: &mut R) -> io::Result<Self::F> {
    <C as ciphersuite::GroupIo>::read_F(reader)
  }
  #[cfg(feature = "alloc")]
  fn read_G<R: io::Read>(reader: &mut R) -> io::Result<Self::G> {
    <C as ciphersuite::GroupIo>::read_G(reader)
  }
}

#[cfg(feature = "ed25519")]
pub use dalek_ff_group::Ed25519;
