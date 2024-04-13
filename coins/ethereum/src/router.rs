use std::{sync::Arc, io, collections::HashSet};

use k256::{
  elliptic_curve::{group::GroupEncoding, sec1},
  ProjectivePoint,
};

use ethers_core::{
  types::{U256, Bytes},
  utils::hex::FromHex,
  abi::{self as eth_abi, AbiEncode},
};
#[cfg(test)]
use ethers_core::types::BlockId;
use ethers_providers::{Provider, Middleware, Http};
use ethers_contract::{EthLogDecode, ContractCall};

pub use crate::{
  Error,
  crypto::{PublicKey, Signature},
  abi::{erc20::TransferFilter, router as abi},
};
use abi::InInstructionFilter;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Coin {
  Ether,
  Erc20([u8; 20]),
}

impl Coin {
  pub fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut kind = [0xff];
    reader.read_exact(&mut kind)?;
    Ok(match kind[0] {
      0 => Coin::Ether,
      1 => {
        let mut address = [0; 20];
        reader.read_exact(&mut address)?;
        Coin::Erc20(address)
      }
      _ => Err(io::Error::other("unrecognized Coin type"))?,
    })
  }

  pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Coin::Ether => writer.write_all(&[0]),
      Coin::Erc20(token) => {
        writer.write_all(&[1])?;
        writer.write_all(token)
      }
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InInstruction {
  pub id: ([u8; 32], u64),
  pub from: [u8; 20],
  pub coin: Coin,
  pub amount: U256,
  pub data: Vec<u8>,
  pub key_at_end_of_block: ProjectivePoint,
}

impl InInstruction {
  pub fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let id = {
      let mut id_hash = [0; 32];
      reader.read_exact(&mut id_hash)?;
      let mut id_pos = [0; 8];
      reader.read_exact(&mut id_pos)?;
      let id_pos = u64::from_le_bytes(id_pos);
      (id_hash, id_pos)
    };

    let mut from = [0; 20];
    reader.read_exact(&mut from)?;

    let coin = Coin::read(reader)?;
    let mut amount = [0; 32];
    reader.read_exact(&mut amount)?;
    let amount = U256::from_little_endian(&amount);

    let mut data_len = [0; 4];
    reader.read_exact(&mut data_len)?;
    let data_len = usize::try_from(u32::from_le_bytes(data_len))
      .map_err(|_| io::Error::other("InInstruction data exceeded 2**32 in length"))?;
    let mut data = vec![0; data_len];
    reader.read_exact(&mut data)?;

    let mut key_at_end_of_block = <ProjectivePoint as GroupEncoding>::Repr::default();
    reader.read_exact(&mut key_at_end_of_block)?;
    let key_at_end_of_block = Option::from(ProjectivePoint::from_bytes(&key_at_end_of_block))
      .ok_or(io::Error::other("InInstruction had key at end of block which wasn't valid"))?;

    Ok(InInstruction { id, from, coin, amount, data, key_at_end_of_block })
  }

  pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.id.0)?;
    writer.write_all(&self.id.1.to_le_bytes())?;

    writer.write_all(&self.from)?;

    self.coin.write(writer)?;
    let mut amount = [0; 32];
    self.amount.to_little_endian(&mut amount);
    writer.write_all(&amount)?;

    writer.write_all(
      &u32::try_from(self.data.len())
        .map_err(|_| {
          io::Error::other("InInstruction being written had data exceeding 2**32 in length")
        })?
        .to_le_bytes(),
    )?;
    writer.write_all(&self.data)?;

    writer.write_all(&self.key_at_end_of_block.to_bytes())
  }
}

/// The contract Serai uses to manage its state.
#[derive(Clone, Debug)]
pub struct Router(Arc<Provider<Http>>, [u8; 20], abi::Router<Provider<Http>>);
impl Router {
  pub(crate) fn code() -> Vec<u8> {
    let bytecode = include_str!("../artifacts/Router.bin");
    Bytes::from_hex(bytecode).expect("compiled-in Router bytecode wasn't valid hex").to_vec()
  }

  pub(crate) fn init_code(key: &PublicKey) -> Vec<u8> {
    let bytecode = Router::code();

    // Append the constructor arguments
    eth_abi::encode_packed(&[
      eth_abi::Token::Bytes(bytecode.as_slice().to_vec()),
      eth_abi::Token::Bytes(key.eth_repr().encode()),
    ])
    .unwrap()
  }

  // This isn't pub in order to force users to use `Deployer::find_router`.
  pub(crate) fn new(provider: Arc<Provider<Http>>, address: [u8; 20]) -> Self {
    Self(provider.clone(), address, abi::Router::new(address, provider))
  }

  pub fn address(&self) -> [u8; 20] {
    self.1
  }

  /// Get the key for Serai at the specified block.
  #[cfg(test)]
  pub async fn serai_key(&self, at: [u8; 32]) -> Result<PublicKey, Error> {
    self
      .2
      .serai_key()
      .block(BlockId::Hash(at.into()))
      .call()
      .await
      .ok()
      .and_then(PublicKey::from_eth_repr)
      .ok_or(Error::ConnectionError)
  }

  /// Get the message to be signed in order to update the key for Serai.
  pub(crate) fn update_serai_key_message(
    chain_id: U256,
    session: U256,
    key: &PublicKey,
  ) -> Vec<u8> {
    let mut buffer = b"updateSeraiKey".to_vec();

    let mut chain_id_bytes = [0; 32];
    chain_id.to_big_endian(&mut chain_id_bytes);
    buffer.extend(&chain_id_bytes);

    let mut session_bytes = [0; 32];
    session.to_big_endian(&mut session_bytes);
    buffer.extend(&session_bytes);

    buffer.extend(&key.eth_repr());
    buffer
  }

  /// Update the key representing Serai.
  pub fn update_serai_key(
    &self,
    public_key: &PublicKey,
    sig: &Signature,
  ) -> ContractCall<Provider<Http>, ()> {
    // TODO: Set a saner gas
    self.2.update_serai_key(public_key.eth_repr(), sig.into()).gas(100_000)
  }

  /// Get the current nonce for the published batches.
  #[cfg(test)]
  pub async fn nonce(&self, at: [u8; 32]) -> Result<U256, Error> {
    self.2.nonce().block(BlockId::Hash(at.into())).call().await.map_err(|_| Error::ConnectionError)
  }

  /// Get the message to be signed in order to update the key for Serai.
  pub(crate) fn execute_message(
    chain_id: U256,
    nonce: U256,
    outs: Vec<abi::OutInstruction>,
  ) -> Vec<u8> {
    ("execute".to_string(), chain_id, nonce, outs).encode()
  }

  /// Execute a batch of `OutInstruction`s.
  pub fn execute(
    &self,
    outs: Vec<abi::OutInstruction>,
    sig: &Signature,
  ) -> ContractCall<Provider<Http>, ()> {
    let gas = 100_000 + ((200_000 + 10_000) * outs.len()); // TODO
    self.2.execute(outs, sig.into()).gas(gas)
  }

  pub async fn in_instructions(
    &self,
    block: u64,
    allowed_tokens: &HashSet<[u8; 20]>,
  ) -> Result<Vec<InInstruction>, Error> {
    let key_at_end_of_block = {
      let filter = self.2.serai_key_updated_filter();
      let filter = filter.from_block(0).to_block(block).address(self.2.address().into());
      let all_keys = filter.query().await.map_err(|_| Error::ConnectionError)?;

      let last_key_x_coordinate =
        all_keys.last().expect("Router existed yet never updated its key").key;

      let mut compressed_point = <ProjectivePoint as GroupEncoding>::Repr::default();
      compressed_point[0] = u8::from(sec1::Tag::CompressedEvenY);
      compressed_point[1 ..].copy_from_slice(&last_key_x_coordinate);

      ProjectivePoint::from_bytes(&compressed_point).expect("router's last key wasn't a valid key")
    };

    let filter = self.2.in_instruction_filter().filter;
    let filter = filter.from_block(block).to_block(block).address(self.2.address());
    let logs = self.0.get_logs(&filter).await.map_err(|_| Error::ConnectionError)?;

    let mut transfer_check = HashSet::new();
    let mut in_instructions = vec![];
    for log in logs {
      // Double check the address which emitted this log
      if log.address.0 != self.1 {
        Err(Error::ConnectionError)?;
      }

      let id = (
        log.block_hash.ok_or(Error::ConnectionError)?.into(),
        log.log_index.ok_or(Error::ConnectionError)?.as_u64(),
      );

      let tx_hash = log.transaction_hash.ok_or(Error::ConnectionError)?;
      let tx = self
        .0
        .get_transaction(tx_hash)
        .await
        .map_err(|_| Error::ConnectionError)?
        .ok_or(Error::ConnectionError)?;

      let log = InInstructionFilter::decode_log(&log.into()).map_err(|_| Error::ConnectionError)?;

      let coin = if log.coin.0 == [0; 20] {
        Coin::Ether
      } else {
        let token = log.coin.0;

        if !allowed_tokens.contains(&token) {
          continue;
        }

        // If this also counts as a top-level transfer via the token, drop it
        //
        // Necessary in order to handle a potential edge case with some theoretical token
        // implementations
        //
        // This will either let it be handled by the top-level transfer hook or will drop it
        // entirely on the side of caution
        if tx.to == Some(token.into()) {
          continue;
        }

        // Get all logs for this TX
        let receipt = self
          .0
          .get_transaction_receipt(tx_hash)
          .await
          .map_err(|_| Error::ConnectionError)?
          .ok_or(Error::ConnectionError)?;
        let tx_logs = receipt.logs;

        // Find a matching transfer log
        let mut found_transfer = false;
        for tx_log in tx_logs {
          let log_index = tx_log.log_index.ok_or(Error::ConnectionError)?.as_u64();
          // Ensure we didn't already use this transfer to check a distinct InInstruction event
          if transfer_check.contains(&log_index) {
            continue;
          }

          // Check if this log is from the token we expected to be transferred
          if tx_log.address.0 != token {
            continue;
          }
          // Check if this is a transfer log
          let Ok(transfer) = TransferFilter::decode_log(&tx_log.into()) else { continue };
          // Check if this is a transfer to us for the expected amount
          if (transfer.to.0 == self.1) && (transfer.value == log.amount) {
            transfer_check.insert(log_index);
            found_transfer = true;
            break;
          }
        }
        if !found_transfer {
          // This shouldn't be a ConnectionError
          // This is an exploit, a non-conforming ERC20, or an invalid connection
          // This should halt the process which is sufficient, yet this is sub-optimal
          // TODO
          Err(Error::ConnectionError)?;
        }

        Coin::Erc20(token)
      };

      in_instructions.push(InInstruction {
        id,
        from: log.from.0,
        coin,
        amount: log.amount,
        data: log.instruction.as_ref().to_vec(),
        key_at_end_of_block,
      });
    }

    Ok(in_instructions)
  }
}
