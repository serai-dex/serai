#![no_std]

pub use std_shims;
pub use serai_db;

pub use flexible_transcript;

pub use dalek_ff_group;
pub use minimal_ed448;

pub use ciphersuite;

pub use prime_field;
pub use short_weierstrass;
pub use secq256k1;
pub use embedwards25519;

pub use schnorr_signatures;

pub use tendermint_machine;

pub use ethereum_schnorr_contract;

#[cfg(feature = "alloc")]
pub mod alloc {
  pub use multiexp;

  pub use dkg;
  pub use dkg_dealer;
  pub use dkg_recovery;
  pub use musig;
  pub use dkg_evrf;

  pub use modular_frost;
  pub use frost_schnorrkel;

  pub use bitcoin_serai;

  pub use serai_client_bitcoin;
  pub use serai_client_ethereum;
}
