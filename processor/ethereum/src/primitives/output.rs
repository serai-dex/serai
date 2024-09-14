use std::io;

use ciphersuite::{Ciphersuite, Secp256k1};

use ethereum_serai::{
  alloy::primitives::U256,
  router::{Coin as EthereumCoin, InInstruction as EthereumInInstruction},
};

use scale::{Encode, Decode};
use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::{
  primitives::{NetworkId, Coin, Amount, Balance},
  networks::ethereum::Address,
};

use primitives::{OutputType, ReceivedOutput};

const DAI: [u8; 20] =
  match const_hex::const_decode_to_array(b"0x6B175474E89094C44Da98b954EedeAC495271d0F") {
    Ok(res) => res,
    Err(_) => panic!("invalid non-test DAI hex address"),
  };

fn coin_to_serai_coin(coin: &EthereumCoin) -> Option<Coin> {
  match coin {
    EthereumCoin::Ether => Some(Coin::Ether),
    EthereumCoin::Erc20(token) => {
      if *token == DAI {
        return Some(Coin::Dai);
      }
      None
    }
  }
}

fn amount_to_serai_amount(coin: Coin, amount: U256) -> Amount {
  assert_eq!(coin.network(), NetworkId::Ethereum);
  assert_eq!(coin.decimals(), 8);
  // Remove 10 decimals so we go from 18 decimals to 8 decimals
  let divisor = U256::from(10_000_000_000u64);
  // This is valid up to 184b, which is assumed for the coins allowed
  Amount(u64::try_from(amount / divisor).unwrap())
}

#[derive(
  Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, BorshSerialize, BorshDeserialize,
)]
pub(crate) struct OutputId(pub(crate) [u8; 40]);
impl Default for OutputId {
  fn default() -> Self {
    Self([0; 40])
  }
}
impl AsRef<[u8]> for OutputId {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}
impl AsMut<[u8]> for OutputId {
  fn as_mut(&mut self) -> &mut [u8] {
    self.0.as_mut()
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Output(pub(crate) EthereumInInstruction);
impl ReceivedOutput<<Secp256k1 as Ciphersuite>::G, Address> for Output {
  type Id = OutputId;
  type TransactionId = [u8; 32];

  // We only scan external outputs as we don't have branch/change/forwards
  fn kind(&self) -> OutputType {
    OutputType::External
  }

  fn id(&self) -> Self::Id {
    let mut id = [0; 40];
    id[.. 32].copy_from_slice(&self.0.id.0);
    id[32 ..].copy_from_slice(&self.0.id.1.to_le_bytes());
    OutputId(id)
  }

  fn transaction_id(&self) -> Self::TransactionId {
    self.0.id.0
  }

  fn key(&self) -> <Secp256k1 as Ciphersuite>::G {
    self.0.key_at_end_of_block
  }

  fn presumed_origin(&self) -> Option<Address> {
    Some(Address::from(self.0.from))
  }

  fn balance(&self) -> Balance {
    let coin = coin_to_serai_coin(&self.0.coin).unwrap_or_else(|| {
      panic!(
        "mapping coin from an EthereumInInstruction with coin {}, which we don't handle.",
        "this never should have been yielded"
      )
    });
    Balance { coin, amount: amount_to_serai_amount(coin, self.0.amount) }
  }
  fn data(&self) -> &[u8] {
    &self.0.data
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    self.0.write(writer)
  }
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    EthereumInInstruction::read(reader).map(Self)
  }
}
