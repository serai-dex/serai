#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
//! Types used when cosigning Serai. For more info, please see `serai-cosign`.
use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{BlockHash, crypto::Public, network_id::ExternalNetworkId};

/// The schnorrkel context to used when signing a cosign.
pub const COSIGN_CONTEXT: &[u8] = b"/serai/coordinator/cosign";

/// An intended cosign.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct CosignIntent {
  /// The global session this cosign is being performed under.
  pub global_session: [u8; 32],
  /// The number of the block to cosign.
  pub block_number: u64,
  /// The hash of the block to cosign.
  pub block_hash: BlockHash,
  /// If this cosign must be handled before further cosigns are.
  pub notable: bool,
}

/// A cosign.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct Cosign {
  /// The global session this cosign is being performed under.
  pub global_session: [u8; 32],
  /// The number of the block to cosign.
  pub block_number: u64,
  /// The hash of the block to cosign.
  pub block_hash: BlockHash,
  /// The actual cosigner.
  pub cosigner: ExternalNetworkId,
}

impl CosignIntent {
  /// Convert this into a `Cosign`.
  pub fn into_cosign(self, cosigner: ExternalNetworkId) -> Cosign {
    let CosignIntent { global_session, block_number, block_hash, notable: _ } = self;
    Cosign { global_session, block_number, block_hash, cosigner }
  }
}

impl Cosign {
  /// The message to sign to sign this cosign.
  ///
  /// This must be signed with schnorrkel, the context set to `COSIGN_CONTEXT`.
  pub fn signature_message(&self) -> Vec<u8> {
    // We use a schnorrkel context to domain-separate this
    borsh::to_vec(self).unwrap()
  }
}

/// A signed cosign.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SignedCosign {
  /// The cosign.
  pub cosign: Cosign,
  /// The signature for the cosign.
  pub signature: [u8; 64],
}

impl SignedCosign {
  /// Verify a cosign's signature.
  pub fn verify_signature(&self, signer: Public) -> bool {
    let Ok(signer) = schnorrkel::PublicKey::from_bytes(&signer.0) else { return false };
    let Ok(signature) = schnorrkel::Signature::from_bytes(&self.signature) else { return false };

    signer.verify_simple(COSIGN_CONTEXT, &self.cosign.signature_message(), &signature).is_ok()
  }
}
