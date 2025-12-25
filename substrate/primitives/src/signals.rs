use zeroize::Zeroize;
use borsh::{BorshSerialize, BorshDeserialize};

use crate::network_id::ExternalNetworkId;

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

#[test]
fn serialize() {
  #[cfg(feature = "scale")]
  use scale::{Encode as _, DecodeAll as _, MaxEncodedLen as _};

  use rand_core::{RngCore as _, OsRng};

  #[cfg(feature = "scale")]
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

  #[cfg(feature = "scale")]
  assert_eq!(Signal::max_encoded_len(), max_encoded_len);
}
