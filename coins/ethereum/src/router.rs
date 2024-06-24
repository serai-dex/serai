use std::{sync::Arc, io, collections::HashSet};

use k256::{
  elliptic_curve::{group::GroupEncoding, sec1},
  ProjectivePoint,
};

use alloy_core::primitives::{hex::FromHex, Address, U256, Bytes, TxKind};
#[cfg(test)]
use alloy_core::primitives::B256;
use alloy_consensus::TxLegacy;

use alloy_sol_types::{SolValue, SolConstructor, SolCall, SolEvent};

use alloy_rpc_types_eth::Filter;
#[cfg(test)]
use alloy_rpc_types_eth::{BlockId, TransactionRequest, TransactionInput};
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

pub use crate::{
  Error,
  crypto::{PublicKey, Signature},
  abi::{erc20::Transfer, router as abi},
};
use abi::{SeraiKeyUpdated, InInstruction as InInstructionEvent, Executed as ExecutedEvent};

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
    let amount = U256::from_le_slice(&amount);

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
    writer.write_all(&self.amount.as_le_bytes())?;

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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Executed {
  pub tx_id: [u8; 32],
  pub nonce: u64,
  pub signature: [u8; 64],
}

/// The contract Serai uses to manage its state.
#[derive(Clone, Debug)]
pub struct Router(Arc<RootProvider<SimpleRequest>>, Address);
impl Router {
  pub(crate) fn code() -> Vec<u8> {
    let bytecode = include_str!("../artifacts/Router.bin");
    Bytes::from_hex(bytecode).expect("compiled-in Router bytecode wasn't valid hex").to_vec()
  }

  pub(crate) fn init_code(key: &PublicKey) -> Vec<u8> {
    let mut bytecode = Self::code();
    // Append the constructor arguments
    bytecode.extend((abi::constructorCall { _seraiKey: key.eth_repr().into() }).abi_encode());
    bytecode
  }

  // This isn't pub in order to force users to use `Deployer::find_router`.
  pub(crate) fn new(provider: Arc<RootProvider<SimpleRequest>>, address: Address) -> Self {
    Self(provider, address)
  }

  pub fn address(&self) -> [u8; 20] {
    **self.1
  }

  /// Get the key for Serai at the specified block.
  #[cfg(test)]
  pub async fn serai_key(&self, at: [u8; 32]) -> Result<PublicKey, Error> {
    let call = TransactionRequest::default()
      .to(self.1)
      .input(TransactionInput::new(abi::seraiKeyCall::new(()).abi_encode().into()));
    let bytes = self
      .0
      .call(&call)
      .block(BlockId::Hash(B256::from(at).into()))
      .await
      .map_err(|_| Error::ConnectionError)?;
    let res =
      abi::seraiKeyCall::abi_decode_returns(&bytes, true).map_err(|_| Error::ConnectionError)?;
    PublicKey::from_eth_repr(res._0.0).ok_or(Error::ConnectionError)
  }

  /// Get the message to be signed in order to update the key for Serai.
  pub(crate) fn update_serai_key_message(chain_id: U256, nonce: U256, key: &PublicKey) -> Vec<u8> {
    let mut buffer = b"updateSeraiKey".to_vec();
    buffer.extend(&chain_id.to_be_bytes::<32>());
    buffer.extend(&nonce.to_be_bytes::<32>());
    buffer.extend(&key.eth_repr());
    buffer
  }

  /// Update the key representing Serai.
  pub fn update_serai_key(&self, public_key: &PublicKey, sig: &Signature) -> TxLegacy {
    // TODO: Set a more accurate gas
    TxLegacy {
      to: TxKind::Call(self.1),
      input: abi::updateSeraiKeyCall::new((public_key.eth_repr().into(), sig.into()))
        .abi_encode()
        .into(),
      gas_limit: 100_000,
      ..Default::default()
    }
  }

  /// Get the current nonce for the published batches.
  #[cfg(test)]
  pub async fn nonce(&self, at: [u8; 32]) -> Result<U256, Error> {
    let call = TransactionRequest::default()
      .to(self.1)
      .input(TransactionInput::new(abi::nonceCall::new(()).abi_encode().into()));
    let bytes = self
      .0
      .call(&call)
      .block(BlockId::Hash(B256::from(at).into()))
      .await
      .map_err(|_| Error::ConnectionError)?;
    let res =
      abi::nonceCall::abi_decode_returns(&bytes, true).map_err(|_| Error::ConnectionError)?;
    Ok(res._0)
  }

  /// Get the message to be signed in order to update the key for Serai.
  pub(crate) fn execute_message(
    chain_id: U256,
    nonce: U256,
    outs: Vec<abi::OutInstruction>,
  ) -> Vec<u8> {
    ("execute".to_string(), chain_id, nonce, outs).abi_encode_params()
  }

  /// Execute a batch of `OutInstruction`s.
  pub fn execute(&self, outs: &[abi::OutInstruction], sig: &Signature) -> TxLegacy {
    TxLegacy {
      to: TxKind::Call(self.1),
      input: abi::executeCall::new((outs.to_vec(), sig.into())).abi_encode().into(),
      // TODO
      gas_limit: 100_000 + ((200_000 + 10_000) * u128::try_from(outs.len()).unwrap()),
      ..Default::default()
    }
  }

  pub async fn key_at_end_of_block(&self, block: u64) -> Result<Option<ProjectivePoint>, Error> {
    let filter = Filter::new().from_block(0).to_block(block).address(self.1);
    let filter = filter.event_signature(SeraiKeyUpdated::SIGNATURE_HASH);
    let all_keys = self.0.get_logs(&filter).await.map_err(|_| Error::ConnectionError)?;
    if all_keys.is_empty() {
      return Ok(None);
    };

    let last_key_x_coordinate_log = all_keys.last().ok_or(Error::ConnectionError)?;
    let last_key_x_coordinate = last_key_x_coordinate_log
      .log_decode::<SeraiKeyUpdated>()
      .map_err(|_| Error::ConnectionError)?
      .inner
      .data
      .key;

    let mut compressed_point = <ProjectivePoint as GroupEncoding>::Repr::default();
    compressed_point[0] = u8::from(sec1::Tag::CompressedEvenY);
    compressed_point[1 ..].copy_from_slice(last_key_x_coordinate.as_slice());

    let key =
      Option::from(ProjectivePoint::from_bytes(&compressed_point)).ok_or(Error::ConnectionError)?;
    Ok(Some(key))
  }

  pub async fn in_instructions(
    &self,
    block: u64,
    allowed_tokens: &HashSet<[u8; 20]>,
  ) -> Result<Vec<InInstruction>, Error> {
    let Some(key_at_end_of_block) = self.key_at_end_of_block(block).await? else {
      return Ok(vec![]);
    };

    let filter = Filter::new().from_block(block).to_block(block).address(self.1);
    let filter = filter.event_signature(InInstructionEvent::SIGNATURE_HASH);
    let logs = self.0.get_logs(&filter).await.map_err(|_| Error::ConnectionError)?;

    let mut transfer_check = HashSet::new();
    let mut in_instructions = vec![];
    for log in logs {
      // Double check the address which emitted this log
      if log.address() != self.1 {
        Err(Error::ConnectionError)?;
      }

      let id = (
        log.block_hash.ok_or(Error::ConnectionError)?.into(),
        log.log_index.ok_or(Error::ConnectionError)?,
      );

      let tx_hash = log.transaction_hash.ok_or(Error::ConnectionError)?;
      let tx = self
        .0
        .get_transaction_by_hash(tx_hash)
        .await
        .ok()
        .flatten()
        .ok_or(Error::ConnectionError)?;

      let log =
        log.log_decode::<InInstructionEvent>().map_err(|_| Error::ConnectionError)?.inner.data;

      let coin = if log.coin.0 == [0; 20] {
        Coin::Ether
      } else {
        let token = *log.coin.0;

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
        let tx_logs = receipt.inner.logs();

        // Find a matching transfer log
        let mut found_transfer = false;
        for tx_log in tx_logs {
          let log_index = tx_log.log_index.ok_or(Error::ConnectionError)?;
          // Ensure we didn't already use this transfer to check a distinct InInstruction event
          if transfer_check.contains(&log_index) {
            continue;
          }

          // Check if this log is from the token we expected to be transferred
          if tx_log.address().0 != token {
            continue;
          }
          // Check if this is a transfer log
          // https://github.com/alloy-rs/core/issues/589
          if tx_log.topics()[0] != Transfer::SIGNATURE_HASH {
            continue;
          }
          let Ok(transfer) = Transfer::decode_log(&tx_log.inner.clone(), true) else { continue };
          // Check if this is a transfer to us for the expected amount
          if (transfer.to == self.1) && (transfer.value == log.amount) {
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
        from: *log.from.0,
        coin,
        amount: log.amount,
        data: log.instruction.as_ref().to_vec(),
        key_at_end_of_block,
      });
    }

    Ok(in_instructions)
  }

  pub async fn executed_commands(&self, block: u64) -> Result<Vec<Executed>, Error> {
    let mut res = vec![];

    {
      let filter = Filter::new().from_block(block).to_block(block).address(self.1);
      let filter = filter.event_signature(SeraiKeyUpdated::SIGNATURE_HASH);
      let logs = self.0.get_logs(&filter).await.map_err(|_| Error::ConnectionError)?;

      for log in logs {
        // Double check the address which emitted this log
        if log.address() != self.1 {
          Err(Error::ConnectionError)?;
        }

        let tx_id = log.transaction_hash.ok_or(Error::ConnectionError)?.into();

        let log =
          log.log_decode::<SeraiKeyUpdated>().map_err(|_| Error::ConnectionError)?.inner.data;

        let mut signature = [0; 64];
        signature[.. 32].copy_from_slice(log.signature.c.as_ref());
        signature[32 ..].copy_from_slice(log.signature.s.as_ref());
        res.push(Executed {
          tx_id,
          nonce: log.nonce.try_into().map_err(|_| Error::ConnectionError)?,
          signature,
        });
      }
    }

    {
      let filter = Filter::new().from_block(block).to_block(block).address(self.1);
      let filter = filter.event_signature(ExecutedEvent::SIGNATURE_HASH);
      let logs = self.0.get_logs(&filter).await.map_err(|_| Error::ConnectionError)?;

      for log in logs {
        // Double check the address which emitted this log
        if log.address() != self.1 {
          Err(Error::ConnectionError)?;
        }

        let tx_id = log.transaction_hash.ok_or(Error::ConnectionError)?.into();

        let log = log.log_decode::<ExecutedEvent>().map_err(|_| Error::ConnectionError)?.inner.data;

        let mut signature = [0; 64];
        signature[.. 32].copy_from_slice(log.signature.c.as_ref());
        signature[32 ..].copy_from_slice(log.signature.s.as_ref());
        res.push(Executed {
          tx_id,
          nonce: log.nonce.try_into().map_err(|_| Error::ConnectionError)?,
          signature,
        });
      }
    }

    Ok(res)
  }

  #[cfg(feature = "tests")]
  pub fn key_updated_filter(&self) -> Filter {
    Filter::new().address(self.1).event_signature(SeraiKeyUpdated::SIGNATURE_HASH)
  }
  #[cfg(feature = "tests")]
  pub fn executed_filter(&self) -> Filter {
    Filter::new().address(self.1).event_signature(ExecutedEvent::SIGNATURE_HASH)
  }
}
