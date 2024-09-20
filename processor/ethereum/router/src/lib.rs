#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::{sync::Arc, io, collections::HashSet};

use group::ff::PrimeField;

use alloy_core::primitives::{hex::FromHex, Address, U256, Bytes, TxKind};
use alloy_consensus::TxLegacy;

use alloy_sol_types::{SolValue, SolConstructor, SolCall, SolEvent};

use alloy_rpc_types_eth::Filter;
use alloy_transport::{TransportErrorKind, RpcError};
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

use ethereum_schnorr::{PublicKey, Signature};
use ethereum_deployer::Deployer;
use erc20::{Transfer, Erc20};

use serai_client::networks::ethereum::Address as SeraiAddress;

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod _abi {
  include!(concat!(env!("OUT_DIR"), "/serai-processor-ethereum-router/router.rs"));
}
use _abi::Router as abi;
use abi::{
  SeraiKeyUpdated as SeraiKeyUpdatedEvent, InInstruction as InInstructionEvent,
  Executed as ExecutedEvent,
};

impl From<&Signature> for abi::Signature {
  fn from(signature: &Signature) -> Self {
    Self {
      c: <[u8; 32]>::from(signature.c().to_repr()).into(),
      s: <[u8; 32]>::from(signature.s().to_repr()).into(),
    }
  }
}

/// A coin on Ethereum.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Coin {
  /// Ether, the native coin of Ethereum.
  Ether,
  /// An ERC20 token.
  Erc20([u8; 20]),
}

impl Coin {
  fn address(&self) -> Address {
    (match self {
      Coin::Ether => [0; 20],
      Coin::Erc20(address) => *address,
    })
    .into()
  }

  /// Read a `Coin`.
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

  /// Write the `Coin`.
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

/// An InInstruction from the Router.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InInstruction {
  /// The ID for this `InInstruction`.
  pub id: ([u8; 32], u64),
  /// The address which transferred these coins to Serai.
  pub from: [u8; 20],
  /// The coin transferred.
  pub coin: Coin,
  /// The amount transferred.
  pub amount: U256,
  /// The data associated with the transfer.
  pub data: Vec<u8>,
}

impl InInstruction {
  /// Read an `InInstruction`.
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

    Ok(InInstruction { id, from, coin, amount, data })
  }

  /// Write the `InInstruction`.
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
    writer.write_all(&self.data)
  }
}

/// A list of `OutInstruction`s.
#[derive(Clone)]
pub struct OutInstructions(Vec<abi::OutInstruction>);
impl From<&[(SeraiAddress, U256)]> for OutInstructions {
  fn from(outs: &[(SeraiAddress, U256)]) -> Self {
    Self(
      outs
        .iter()
        .map(|(address, amount)| {
          #[allow(non_snake_case)]
          let (destinationType, destination) = match address {
            SeraiAddress::Address(address) => (
              abi::DestinationType::Address,
              (abi::AddressDestination { destination: Address::from(address) }).abi_encode(),
            ),
            SeraiAddress::Contract(contract) => (
              abi::DestinationType::Code,
              (abi::CodeDestination {
                gas_limit: contract.gas_limit(),
                code: contract.code().to_vec().into(),
              })
              .abi_encode(),
            ),
          };
          abi::OutInstruction { destinationType, destination: destination.into(), value: *amount }
        })
        .collect(),
    )
  }
}

/// An action which was executed by the Router.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Executed {
  /// Set a new key.
  SetKey {
    /// The nonce this was done with.
    nonce: u64,
    /// The key set.
    key: [u8; 32],
  },
  /// Executed Batch.
  Batch {
    /// The nonce this was done with.
    nonce: u64,
    /// The hash of the signed message for the Batch executed.
    message_hash: [u8; 32],
  },
}

impl Executed {
  /// The nonce consumed by this executed event.
  pub fn nonce(&self) -> u64 {
    match self {
      Executed::SetKey { nonce, .. } | Executed::Batch { nonce, .. } => *nonce,
    }
  }

  /// Write the Executed.
  pub fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    match self {
      Self::SetKey { nonce, key } => {
        writer.write_all(&[0])?;
        writer.write_all(&nonce.to_le_bytes())?;
        writer.write_all(key)
      }
      Self::Batch { nonce, message_hash } => {
        writer.write_all(&[1])?;
        writer.write_all(&nonce.to_le_bytes())?;
        writer.write_all(message_hash)
      }
    }
  }

  /// Read an Executed.
  pub fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let mut kind = [0xff];
    reader.read_exact(&mut kind)?;
    if kind[0] >= 2 {
      Err(io::Error::other("unrecognized type of Executed"))?;
    }

    let mut nonce = [0; 8];
    reader.read_exact(&mut nonce)?;
    let nonce = u64::from_le_bytes(nonce);

    let mut payload = [0; 32];
    reader.read_exact(&mut payload)?;

    Ok(match kind[0] {
      0 => Self::SetKey { nonce, key: payload },
      1 => Self::Batch { nonce, message_hash: payload },
      _ => unreachable!(),
    })
  }
}

/// A view of the Router for Serai.
#[derive(Clone, Debug)]
pub struct Router(Arc<RootProvider<SimpleRequest>>, Address);
impl Router {
  fn code() -> Vec<u8> {
    const BYTECODE: &[u8] =
      include_bytes!(concat!(env!("OUT_DIR"), "/serai-processor-ethereum-router/Router.bin"));
    Bytes::from_hex(BYTECODE).expect("compiled-in Router bytecode wasn't valid hex").to_vec()
  }

  fn init_code(key: &PublicKey) -> Vec<u8> {
    let mut bytecode = Self::code();
    // Append the constructor arguments
    bytecode.extend((abi::constructorCall { initialSeraiKey: key.eth_repr().into() }).abi_encode());
    bytecode
  }

  /// Create a new view of the Router.
  ///
  /// This performs an on-chain lookup for the first deployed Router constructed with this public
  /// key. This lookup is of a constant amount of calls and does not read any logs.
  pub async fn new(
    provider: Arc<RootProvider<SimpleRequest>>,
    initial_serai_key: &PublicKey,
  ) -> Result<Option<Self>, RpcError<TransportErrorKind>> {
    let Some(deployer) = Deployer::new(provider.clone()).await? else {
      return Ok(None);
    };
    let Some(deployment) = deployer
      .find_deployment(ethereum_primitives::keccak256(Self::init_code(initial_serai_key)))
      .await?
    else {
      return Ok(None);
    };
    Ok(Some(Self(provider, deployment)))
  }

  /// The address of the router.
  pub fn address(&self) -> Address {
    self.1
  }

  /// Get the message to be signed in order to update the key for Serai.
  pub fn update_serai_key_message(chain_id: U256, nonce: u64, key: &PublicKey) -> Vec<u8> {
    (
      "updateSeraiKey",
      chain_id,
      U256::try_from(nonce).expect("couldn't convert u64 to u256"),
      key.eth_repr(),
    )
      .abi_encode_packed()
  }

  /// Construct a transaction to update the key representing Serai.
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

  /// Get the message to be signed in order to execute a series of `OutInstruction`s.
  pub fn execute_message(
    chain_id: U256,
    nonce: u64,
    coin: Coin,
    fee: U256,
    outs: OutInstructions,
  ) -> Vec<u8> {
    ("execute", chain_id, U256::try_from(nonce).unwrap(), coin.address(), fee, outs.0).abi_encode()
  }

  /// Construct a transaction to execute a batch of `OutInstruction`s.
  pub fn execute(&self, coin: Coin, fee: U256, outs: OutInstructions, sig: &Signature) -> TxLegacy {
    let outs_len = outs.0.len();
    TxLegacy {
      to: TxKind::Call(self.1),
      input: abi::executeCall::new((coin.address(), fee, outs.0, sig.into())).abi_encode().into(),
      // TODO
      gas_limit: 100_000 + ((200_000 + 10_000) * u128::try_from(outs_len).unwrap()),
      ..Default::default()
    }
  }

  /// Fetch the `InInstruction`s emitted by the Router from this block.
  pub async fn in_instructions(
    &self,
    block: u64,
    allowed_tokens: &HashSet<[u8; 20]>,
  ) -> Result<Vec<InInstruction>, RpcError<TransportErrorKind>> {
    // The InInstruction events for this block
    let filter = Filter::new().from_block(block).to_block(block).address(self.1);
    let filter = filter.event_signature(InInstructionEvent::SIGNATURE_HASH);
    let logs = self.0.get_logs(&filter).await?;

    /*
      We check that for all InInstructions for ERC20s emitted, a corresponding transfer occurred.
      In order to prevent a transfer from being used to justify multiple distinct InInstructions,
      we insert the transfer's log index into this HashSet.
    */
    let mut transfer_check = HashSet::new();

    let mut in_instructions = vec![];
    for log in logs {
      // Double check the address which emitted this log
      if log.address() != self.1 {
        Err(TransportErrorKind::Custom(
          "node returned a log from a different address than requested".to_string().into(),
        ))?;
      }

      let id = (
        log
          .block_hash
          .ok_or_else(|| {
            TransportErrorKind::Custom("log didn't have its block hash set".to_string().into())
          })?
          .into(),
        log.log_index.ok_or_else(|| {
          TransportErrorKind::Custom("log didn't have its index set".to_string().into())
        })?,
      );

      let tx_hash = log.transaction_hash.ok_or_else(|| {
        TransportErrorKind::Custom("log didn't have its transaction hash set".to_string().into())
      })?;

      let log = log
        .log_decode::<InInstructionEvent>()
        .map_err(|e| {
          TransportErrorKind::Custom(
            format!("filtered to InInstructionEvent yet couldn't decode log: {e:?}").into(),
          )
        })?
        .inner
        .data;

      let coin = if log.coin.0 == [0; 20] {
        Coin::Ether
      } else {
        let token = *log.coin.0;

        if !allowed_tokens.contains(&token) {
          continue;
        }

        // Get all logs for this TX
        let receipt = self.0.get_transaction_receipt(tx_hash).await?.ok_or_else(|| {
          TransportErrorKind::Custom(
            "node didn't have the receipt for a transaction it had".to_string().into(),
          )
        })?;
        let tx_logs = receipt.inner.logs();

        /*
          The transfer which causes an InInstruction event won't be a top-level transfer.
          Accordingly, when looking for the matching transfer, disregard the top-level transfer (if
          one exists).
        */
        if let Some(matched) = Erc20::match_top_level_transfer(&self.0, tx_hash, self.1).await? {
          // Mark this log index as used so it isn't used again
          transfer_check.insert(matched.log_index);
        }

        // Find a matching transfer log
        let mut found_transfer = false;
        for tx_log in tx_logs {
          let log_index = tx_log.log_index.ok_or_else(|| {
            TransportErrorKind::Custom(
              "log in transaction receipt didn't have its log index set".to_string().into(),
            )
          })?;

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
          if tx_log.topics().first() != Some(&Transfer::SIGNATURE_HASH) {
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
          // This shouldn't be a simple error
          // This is an exploit, a non-conforming ERC20, or a malicious connection
          // This should halt the process. While this is sufficient, it's sub-optimal
          // TODO
          Err(TransportErrorKind::Custom(
            "ERC20 InInstruction with no matching transfer log".to_string().into(),
          ))?;
        }

        Coin::Erc20(token)
      };

      in_instructions.push(InInstruction {
        id,
        from: *log.from.0,
        coin,
        amount: log.amount,
        data: log.instruction.as_ref().to_vec(),
      });
    }

    Ok(in_instructions)
  }

  /// Fetch the executed actions from this block.
  pub async fn executed(&self, block: u64) -> Result<Vec<Executed>, RpcError<TransportErrorKind>> {
    let mut res = vec![];

    {
      let filter = Filter::new().from_block(block).to_block(block).address(self.1);
      let filter = filter.event_signature(SeraiKeyUpdatedEvent::SIGNATURE_HASH);
      let logs = self.0.get_logs(&filter).await?;

      for log in logs {
        // Double check the address which emitted this log
        if log.address() != self.1 {
          Err(TransportErrorKind::Custom(
            "node returned a log from a different address than requested".to_string().into(),
          ))?;
        }

        let log = log
          .log_decode::<SeraiKeyUpdatedEvent>()
          .map_err(|e| {
            TransportErrorKind::Custom(
              format!("filtered to SeraiKeyUpdatedEvent yet couldn't decode log: {e:?}").into(),
            )
          })?
          .inner
          .data;

        res.push(Executed::SetKey {
          nonce: log.nonce.try_into().map_err(|e| {
            TransportErrorKind::Custom(format!("filtered to convert nonce to u64: {e:?}").into())
          })?,
          key: log.key.into(),
        });
      }
    }

    {
      let filter = Filter::new().from_block(block).to_block(block).address(self.1);
      let filter = filter.event_signature(ExecutedEvent::SIGNATURE_HASH);
      let logs = self.0.get_logs(&filter).await?;

      for log in logs {
        // Double check the address which emitted this log
        if log.address() != self.1 {
          Err(TransportErrorKind::Custom(
            "node returned a log from a different address than requested".to_string().into(),
          ))?;
        }

        let log = log
          .log_decode::<ExecutedEvent>()
          .map_err(|e| {
            TransportErrorKind::Custom(
              format!("filtered to ExecutedEvent yet couldn't decode log: {e:?}").into(),
            )
          })?
          .inner
          .data;

        res.push(Executed::Batch {
          nonce: log.nonce.try_into().map_err(|e| {
            TransportErrorKind::Custom(format!("filtered to convert nonce to u64: {e:?}").into())
          })?,
          message_hash: log.message_hash.into(),
        });
      }
    }

    res.sort_by_key(Executed::nonce);

    Ok(res)
  }
}
