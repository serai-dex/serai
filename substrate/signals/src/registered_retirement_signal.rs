use borsh::{BorshSerialize, BorshDeserialize};

use serai_abi::primitives::{
  borsh_as_scale, validator_sets::Session, address::SeraiAddress, signals::*,
};

/// A retirement signal, registered on chain.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct RegisteredRetirementSignal {
  /// The registrant of this signal.
  pub registrant: SeraiAddress,
  /// The protocol to retire in favor of.
  pub in_favor_of: ProtocolId,
  /// The Serai session this signal was registered during.
  pub registered_at: Session,
}
borsh_as_scale!(RegisteredRetirementSignal);

impl RegisteredRetirementSignal {
  /// The ID of this signal.
  pub fn id(&self) -> SignalId {
    sp_core::blake2_256(&borsh::to_vec(self).unwrap())
  }
}

#[test]
fn registered_retirement_signal() {
  use rand_core::{RngCore as _, OsRng};

  use scale::{Encode as _, DecodeAll as _};

  for _ in 0 .. 100 {
    let mut registrant = [0; 32];
    OsRng.fill_bytes(&mut registrant);
    let mut in_favor_of = [0; 32];
    OsRng.fill_bytes(&mut in_favor_of);
    let registrant = SeraiAddress(registrant);

    #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
    let registered_at = Session(OsRng.next_u64() as u32);

    let signal = RegisteredRetirementSignal { registrant, in_favor_of, registered_at };

    assert_eq!(
      RegisteredRetirementSignal::decode_all(&mut signal.encode().as_slice()).unwrap(),
      signal
    );
  }
}
