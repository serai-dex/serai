use std::io;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Secp256k1};

use alloy_core::primitives::U256;

use scale::{Encode, Decode};
use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::{
  primitives::{NetworkId, Coin, Amount, Balance},
  networks::ethereum::Address,
};

use primitives::{OutputType, ReceivedOutput};
use ethereum_router::{Coin as EthereumCoin, InInstruction as EthereumInInstruction};

use crate::{DAI, ETHER_DUST};

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
pub(crate) enum Output {
  Output { key: <Secp256k1 as Ciphersuite>::G, instruction: EthereumInInstruction },
  Eventuality { key: <Secp256k1 as Ciphersuite>::G, nonce: u64 },
}
impl ReceivedOutput<<Secp256k1 as Ciphersuite>::G, Address> for Output {
  type Id = OutputId;
  type TransactionId = [u8; 32];

  fn kind(&self) -> OutputType {
    match self {
      // All outputs received are External
      Output::Output { .. } => OutputType::External,
      // Yet upon Eventuality completions, we report a Change output to ensure synchrony per the
      // scanner's documented bounds
      Output::Eventuality { .. } => OutputType::Change,
    }
  }

  fn id(&self) -> Self::Id {
    match self {
      Output::Output { key: _, instruction } => {
        let mut id = [0; 40];
        id[.. 32].copy_from_slice(&instruction.id.0);
        id[32 ..].copy_from_slice(&instruction.id.1.to_le_bytes());
        OutputId(id)
      }
      // Yet upon Eventuality completions, we report a Change output to ensure synchrony per the
      // scanner's documented bounds
      Output::Eventuality { key: _, nonce } => {
        let mut id = [0; 40];
        id[.. 8].copy_from_slice(&nonce.to_le_bytes());
        OutputId(id)
      }
    }
  }

  fn transaction_id(&self) -> Self::TransactionId {
    match self {
      Output::Output { key: _, instruction } => instruction.id.0,
      Output::Eventuality { key: _, nonce } => {
        let mut id = [0; 32];
        id[.. 8].copy_from_slice(&nonce.to_le_bytes());
        id
      }
    }
  }

  fn key(&self) -> <Secp256k1 as Ciphersuite>::G {
    match self {
      Output::Output { key, .. } | Output::Eventuality { key, .. } => *key,
    }
  }

  fn presumed_origin(&self) -> Option<Address> {
    match self {
      Output::Output { key: _, instruction } => Some(Address::from(instruction.from)),
      Output::Eventuality { .. } => None,
    }
  }

  fn balance(&self) -> Balance {
    match self {
      Output::Output { key: _, instruction } => {
        let coin = coin_to_serai_coin(&instruction.coin).unwrap_or_else(|| {
          panic!(
            "mapping coin from an EthereumInInstruction with coin {}, which we don't handle.",
            "this never should have been yielded"
          )
        });
        Balance { coin, amount: amount_to_serai_amount(coin, instruction.amount) }
      }
      Output::Eventuality { .. } => Balance { coin: Coin::Ether, amount: ETHER_DUST },
    }
  }
  fn data(&self) -> &[u8] {
    match self {
      Output::Output { key: _, instruction } => &instruction.data,
      Output::Eventuality { .. } => &[],
    }
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Output::Output { key, instruction } => {
        writer.write_all(&[0])?;
        writer.write_all(key.to_bytes().as_ref())?;
        instruction.write(writer)
      }
      Output::Eventuality { key, nonce } => {
        writer.write_all(&[1])?;
        writer.write_all(key.to_bytes().as_ref())?;
        writer.write_all(&nonce.to_le_bytes())
      }
    }
  }
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0xff];
    reader.read_exact(&mut kind)?;
    if kind[0] >= 2 {
      Err(io::Error::other("unknown Output type"))?;
    }

    Ok(match kind[0] {
      0 => {
        let key = Secp256k1::read_G(reader)?;
        let instruction = EthereumInInstruction::read(reader)?;
        Self::Output { key, instruction }
      }
      1 => {
        let key = Secp256k1::read_G(reader)?;
        let mut nonce = [0; 8];
        reader.read_exact(&mut nonce)?;
        let nonce = u64::from_le_bytes(nonce);
        Self::Eventuality { key, nonce }
      }
      _ => unreachable!(),
    })
  }
}
