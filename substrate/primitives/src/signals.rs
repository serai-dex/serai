use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use crate::{network_id::ExternalNetworkId, address::SeraiAddress};

/// The ID of an protocol.
pub type ProtocolId = [u8; 32];
/// The ID of a signal.
pub type SignalId = [u8; 32];

/// A signal.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub enum Signal {
  /// A signal to retire the current protocol.
  Retire {
    /// The ID of the retirement signal being favored.
    signal_id: SignalId,
  },
  /// A signal to halt an external network.
  Halt(ExternalNetworkId),
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(Signal);

/// A retirement signal, registered on chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct RegisteredRetirementSignal {
  /// The protocol to retire in favor of.
  pub in_favor_of: ProtocolId,
  /// The registrant of this signal.
  pub registrant: SeraiAddress,
  /// The block number this was registered at.
  pub registered_at: u64,
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(RegisteredRetirementSignal);

impl RegisteredRetirementSignal {
  /// The ID of this signal.
  pub fn id(&self) -> SignalId {
    sp_core::blake2_256(&borsh::to_vec(self).unwrap())
  }
}

#[test]
fn serialize() {
  use rand_core::{RngCore as _, OsRng};

  #[cfg(feature = "scale")]
  use scale::{Encode as _, DecodeAll as _, MaxEncodedLen as _};

  {
    let mut max_encoded_len = 0;

    {
      let mut signal_id = [0; 32];
      OsRng.fill_bytes(&mut signal_id);
      let signal = Signal::Retire { signal_id };

      assert_eq!(
        Signal::deserialize_reader(&mut borsh::to_vec(&signal).unwrap().as_slice()).unwrap(),
        signal
      );

      #[cfg(feature = "scale")]
      {
        assert_eq!(borsh::to_vec(&signal).unwrap(), signal.encode());
        assert_eq!(Signal::decode_all(&mut signal.encode().as_slice()).unwrap(), signal);
        max_encoded_len = max_encoded_len.max(signal.encode().len());
      }
    }

    for network_id in ExternalNetworkId::all() {
      let signal = Signal::Halt(network_id);

      assert_eq!(
        Signal::deserialize_reader(&mut borsh::to_vec(&signal).unwrap().as_slice()).unwrap(),
        signal
      );

      #[cfg(feature = "scale")]
      {
        assert_eq!(borsh::to_vec(&signal).unwrap(), signal.encode());
        assert_eq!(Signal::decode_all(&mut signal.encode().as_slice()).unwrap(), signal);
        max_encoded_len = max_encoded_len.max(signal.encode().len());
      }
    }

    assert_eq!(Signal::max_encoded_len(), max_encoded_len);
  }

  {
    let mut in_favor_of = [0; 32];
    OsRng.fill_bytes(&mut in_favor_of);
    let mut registrant = [0; 32];
    OsRng.fill_bytes(&mut registrant);
    let registrant = SeraiAddress(registrant);
    let registered_at = OsRng.next_u64();

    let signal = RegisteredRetirementSignal { in_favor_of, registrant, registered_at };

    assert_eq!(
      RegisteredRetirementSignal::deserialize_reader(
        &mut borsh::to_vec(&signal).unwrap().as_slice()
      )
      .unwrap(),
      signal
    );

    #[cfg(feature = "scale")]
    {
      assert_eq!(borsh::to_vec(&signal).unwrap(), signal.encode());
      assert_eq!(
        RegisteredRetirementSignal::decode_all(&mut signal.encode().as_slice()).unwrap(),
        signal
      );
      assert!(signal.encode().len() <= RegisteredRetirementSignal::max_encoded_len());
    }
  }
}
