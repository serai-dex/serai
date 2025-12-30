use scale::{Encode, Decode, MaxEncodedLen};

use serai_abi::primitives::{address::SeraiAddress, signals::*};

/// A retirement signal, registered on chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen)]
pub struct RegisteredRetirementSignal {
  /// The registrant of this signal.
  pub registrant: SeraiAddress,
  /// The protocol to retire in favor of.
  pub in_favor_of: ProtocolId,
  /// The slot number this was registered at.
  pub registered_at: u64,
}

impl RegisteredRetirementSignal {
  /// The ID of this signal.
  pub fn id(&self) -> SignalId {
    /*
      This on-purposely doesn't bind to `registered_at` to ensure the Serai protocol doesn't
      commit to the slot numbering system of BABE, which we use for the lifetime of signals.

      The slot system is still implicitly committed to, due to it deciding when rotations occur
      for the validator sets, but it isn't otherwise committed to within our wire format. This
      offers _some_ flexibility in how it's viewed in the future.
    */
    sp_core::blake2_256(&borsh::to_vec(&(self.registrant, self.in_favor_of)).unwrap())
  }
}

#[test]
fn registered_retirement_signal() {
  use scale::DecodeAll as _;
  use rand_core::{RngCore as _, OsRng};

  for _ in 0 .. 100 {
    let mut registrant = [0; 32];
    OsRng.fill_bytes(&mut registrant);
    let mut in_favor_of = [0; 32];
    OsRng.fill_bytes(&mut in_favor_of);
    let registrant = SeraiAddress(registrant);
    let registered_at = OsRng.next_u64();

    let signal = RegisteredRetirementSignal { registrant, in_favor_of, registered_at };

    assert_eq!(
      RegisteredRetirementSignal::decode_all(&mut signal.encode().as_slice()).unwrap(),
      signal
    );
    assert_eq!(signal.encode().len(), RegisteredRetirementSignal::max_encoded_len());
  }
}
