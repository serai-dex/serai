#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::ops::RangeInclusive;
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use borsh::{BorshSerialize, BorshDeserialize};

use group::ff::PrimeField;

use alloy_core::primitives::{hex, Address, U256, TxKind};
use alloy_sol_types::{SolValue, SolConstructor, SolCall, SolEvent};

use alloy_consensus::TxLegacy;

use alloy_rpc_types_eth::{BlockId, Log, Filter, TransactionInput, TransactionRequest};
use alloy_transport::{TransportErrorKind, RpcError};
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

use scale::Encode;
use serai_client::{
  in_instructions::primitives::Shorthand, networks::ethereum::Address as SeraiAddress,
};

use ethereum_primitives::LogIndex;
use ethereum_schnorr::{PublicKey, Signature};
use ethereum_deployer::Deployer;
use erc20::{Transfer, TopLevelTransfer, TopLevelTransfers, Erc20};

use futures_util::stream::{StreamExt, FuturesUnordered};

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod _irouter_abi {
  alloy_sol_macro::sol!("contracts/IRouter.sol");
}

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod _router_abi {
  include!(concat!(env!("OUT_DIR"), "/serai-processor-ethereum-router/router.rs"));
}

mod abi {
  pub use super::_router_abi::IRouterWithoutCollisions::*;
  pub use super::_router_abi::IRouter::*;
  pub use super::_router_abi::Router::constructorCall;
}
use abi::{
  NextSeraiKeySet as NextSeraiKeySetEvent, SeraiKeyUpdated as SeraiKeyUpdatedEvent,
  InInstruction as InInstructionEvent, Batch as BatchEvent, EscapeHatch as EscapeHatchEvent,
  Escaped as EscapedEvent,
};

mod gas;

#[cfg(test)]
mod tests;

impl From<&Signature> for abi::Signature {
  fn from(signature: &Signature) -> Self {
    Self {
      c: <[u8; 32]>::from(signature.c().to_repr()).into(),
      s: <[u8; 32]>::from(signature.s().to_repr()).into(),
    }
  }
}

/// A coin on Ethereum.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, BorshSerialize, BorshDeserialize)]
pub enum Coin {
  /// Ether, the native coin of Ethereum.
  Ether,
  /// An ERC20 token.
  Erc20(
    #[borsh(
      serialize_with = "ethereum_primitives::serialize_address",
      deserialize_with = "ethereum_primitives::deserialize_address"
    )]
    Address,
  ),
}
impl From<Coin> for Address {
  fn from(coin: Coin) -> Address {
    match coin {
      Coin::Ether => Address::ZERO,
      Coin::Erc20(address) => address,
    }
  }
}
impl From<Address> for Coin {
  fn from(address: Address) -> Coin {
    if address == Address::ZERO {
      Coin::Ether
    } else {
      Coin::Erc20(address)
    }
  }
}

/// An InInstruction from the Router.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct InInstruction {
  /// The ID for this `InInstruction`.
  pub id: LogIndex,
  /// The hash of the transaction which caused this.
  pub transaction_hash: [u8; 32],
  /// The address which transferred these coins to Serai.
  #[borsh(
    serialize_with = "ethereum_primitives::serialize_address",
    deserialize_with = "ethereum_primitives::deserialize_address"
  )]
  pub from: Address,
  /// The coin transferred.
  pub coin: Coin,
  /// The amount transferred.
  #[borsh(
    serialize_with = "ethereum_primitives::serialize_u256",
    deserialize_with = "ethereum_primitives::deserialize_u256"
  )]
  pub amount: U256,
  /// The data associated with the transfer.
  pub data: Vec<u8>,
}

impl From<&(SeraiAddress, U256)> for abi::OutInstruction {
  fn from((address, amount): &(SeraiAddress, U256)) -> Self {
    #[allow(non_snake_case)]
    let (destinationType, destination) = match address {
      SeraiAddress::Address(address) => {
        // Per the documentation, `DestinationType::Address`'s value is an ABI-encoded address
        (abi::DestinationType::Address, (Address::from(address)).abi_encode())
      }
      SeraiAddress::Contract(contract) => (
        abi::DestinationType::Code,
        (abi::CodeDestination {
          gasLimit: contract.gas_limit(),
          code: contract.code().to_vec().into(),
        })
        .abi_encode(),
      ),
    };
    abi::OutInstruction { destinationType, destination: destination.into(), amount: *amount }
  }
}

/// A list of `OutInstruction`s.
#[derive(Clone)]
pub struct OutInstructions(Vec<abi::OutInstruction>);
impl From<&[(SeraiAddress, U256)]> for OutInstructions {
  fn from(outs: &[(SeraiAddress, U256)]) -> Self {
    Self(outs.iter().map(Into::into).collect())
  }
}

/// An action which was executed by the Router.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Executed {
  /// Next key was set.
  NextSeraiKeySet {
    /// The nonce this was done with.
    nonce: u64,
    /// The key set.
    key: [u8; 32],
  },
  /// The next key was updated to.
  SeraiKeyUpdated {
    /// The nonce this was done with.
    nonce: u64,
    /// The key set.
    key: [u8; 32],
  },
  /// Executed batch of `OutInstruction`s.
  Batch {
    /// The nonce this was done with.
    nonce: u64,
    /// The hash of the signed message for the Batch executed.
    message_hash: [u8; 32],
    /// The results of the `OutInstruction`s executed.
    results: Vec<bool>,
  },
  /// The escape hatch was set.
  EscapeHatch {
    /// The nonce this was done with.
    nonce: u64,
    /// The address set to escape to.
    #[borsh(
      serialize_with = "ethereum_primitives::serialize_address",
      deserialize_with = "ethereum_primitives::deserialize_address"
    )]
    escape_to: Address,
  },
}

impl Executed {
  /// The nonce consumed by this executed event.
  ///
  /// This is a `u64` despite the contract defining the nonce as a `u256`. Since the nonce is
  /// incremental, the u64 will never be exhausted.
  pub fn nonce(&self) -> u64 {
    match self {
      Executed::NextSeraiKeySet { nonce, .. } |
      Executed::SeraiKeyUpdated { nonce, .. } |
      Executed::Batch { nonce, .. } |
      Executed::EscapeHatch { nonce, .. } => *nonce,
    }
  }
}

/// An Escape from the Router.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct Escape {
  /// The coin escaped.
  pub coin: Coin,
  /// The amount escaped.
  #[borsh(
    serialize_with = "ethereum_primitives::serialize_u256",
    deserialize_with = "ethereum_primitives::deserialize_u256"
  )]
  pub amount: U256,
}

/// A view of the Router for Serai.
#[derive(Clone, Debug)]
pub struct Router {
  provider: Arc<RootProvider<SimpleRequest>>,
  address: Address,
  empty_execute_gas: HashMap<Coin, u64>,
}
impl Router {
  fn init_code(key: &PublicKey) -> Vec<u8> {
    const INITCODE: &[u8] = {
      const INITCODE_HEX: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/serai-processor-ethereum-router/Router.bin"));
      const INITCODE: [u8; INITCODE_HEX.len() / 2] =
        match hex::const_decode_to_array::<{ INITCODE_HEX.len() / 2 }>(INITCODE_HEX) {
          Ok(bytecode) => bytecode,
          Err(_) => panic!("Router.bin did not contain valid hex"),
        };
      &INITCODE
    };

    // Append the constructor arguments
    let mut initcode = INITCODE.to_vec();
    initcode.extend((abi::constructorCall { initialSeraiKey: key.eth_repr().into() }).abi_encode());
    initcode
  }

  /// Obtain the transaction to deploy this contract.
  ///
  /// This transaction assumes the `Deployer` has already been deployed. The gas limit and gas
  /// price are not set and are left to the caller.
  pub fn deployment_tx(initial_serai_key: &PublicKey) -> TxLegacy {
    Deployer::deploy_tx(Self::init_code(initial_serai_key))
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
    let Some(address) = deployer
      .find_deployment(ethereum_primitives::keccak256(Self::init_code(initial_serai_key)))
      .await?
    else {
      return Ok(None);
    };
    Ok(Some(Self { provider, address, empty_execute_gas: HashMap::new() }))
  }

  /// The address of the router.
  pub fn address(&self) -> Address {
    self.address
  }

  /// Get the message to be signed in order to confirm the next key for Serai.
  pub fn confirm_next_serai_key_message(chain_id: U256, nonce: u64) -> Vec<u8> {
    abi::confirmNextSeraiKeyCall::new((abi::Signature {
      c: chain_id.into(),
      s: U256::try_from(nonce).unwrap().into(),
    },))
    .abi_encode()
  }

  /// Construct a transaction to confirm the next key representing Serai.
  ///
  /// The gas limit and gas price are not set and are left to the caller.
  pub fn confirm_next_serai_key(&self, sig: &Signature) -> TxLegacy {
    TxLegacy {
      to: TxKind::Call(self.address),
      input: abi::confirmNextSeraiKeyCall::new((abi::Signature::from(sig),)).abi_encode().into(),
      ..Default::default()
    }
  }

  /// Get the message to be signed in order to update the key for Serai.
  pub fn update_serai_key_message(chain_id: U256, nonce: u64, key: &PublicKey) -> Vec<u8> {
    abi::updateSeraiKeyCall::new((
      abi::Signature { c: chain_id.into(), s: U256::try_from(nonce).unwrap().into() },
      key.eth_repr().into(),
    ))
    .abi_encode()
  }

  /// Construct a transaction to update the key representing Serai.
  ///
  /// The gas limit and gas price are not set and are left to the caller.
  pub fn update_serai_key(&self, public_key: &PublicKey, sig: &Signature) -> TxLegacy {
    TxLegacy {
      to: TxKind::Call(self.address),
      input: abi::updateSeraiKeyCall::new((
        abi::Signature::from(sig),
        public_key.eth_repr().into(),
      ))
      .abi_encode()
      .into(),
      ..Default::default()
    }
  }

  /// Construct a transaction to send coins with an InInstruction to Serai.
  ///
  /// If coin is an ERC20, this will not create a transaction calling the Router but will create a
  /// top-level transfer of the ERC20 to the Router. This avoids needing to call `approve` before
  /// publishing the transaction calling the Router.
  ///
  /// The gas limit and gas price are not set and are left to the caller.
  pub fn in_instruction(&self, coin: Coin, amount: U256, in_instruction: &Shorthand) -> TxLegacy {
    match coin {
      Coin::Ether => TxLegacy {
        to: self.address.into(),
        input: abi::inInstructionCall::new((coin.into(), amount, in_instruction.encode().into()))
          .abi_encode()
          .into(),
        value: amount,
        ..Default::default()
      },
      Coin::Erc20(erc20) => TxLegacy {
        to: erc20.into(),
        input: erc20::transferWithInInstructionCall::new((
          self.address,
          amount,
          in_instruction.encode().into(),
        ))
        .abi_encode()
        .into(),
        ..Default::default()
      },
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
    abi::executeCall::new((
      abi::Signature { c: chain_id.into(), s: U256::try_from(nonce).unwrap().into() },
      Address::from(coin),
      fee,
      outs.0,
    ))
    .abi_encode()
  }

  /// Construct a transaction to execute a batch of `OutInstruction`s.
  ///
  /// The gas limit and gas price are not set and are left to the caller.
  pub fn execute(&self, coin: Coin, fee: U256, outs: OutInstructions, sig: &Signature) -> TxLegacy {
    TxLegacy {
      to: TxKind::Call(self.address),
      input: abi::executeCall::new((abi::Signature::from(sig), Address::from(coin), fee, outs.0))
        .abi_encode()
        .into(),
      ..Default::default()
    }
  }

  /// Get the message to be signed in order to trigger the escape hatch.
  pub fn escape_hatch_message(chain_id: U256, nonce: u64, escape_to: Address) -> Vec<u8> {
    abi::escapeHatchCall::new((
      abi::Signature { c: chain_id.into(), s: U256::try_from(nonce).unwrap().into() },
      escape_to,
    ))
    .abi_encode()
  }

  /// Construct a transaction to trigger the escape hatch.
  ///
  /// The gas limit and gas price are not set and are left to the caller.
  pub fn escape_hatch(&self, escape_to: Address, sig: &Signature) -> TxLegacy {
    TxLegacy {
      to: TxKind::Call(self.address),
      input: abi::escapeHatchCall::new((abi::Signature::from(sig), escape_to)).abi_encode().into(),
      ..Default::default()
    }
  }

  /// Construct a transaction to escape coins via the escape hatch.
  ///
  /// The gas limit and gas price are not set and are left to the caller.
  pub fn escape(&self, coin: Coin) -> TxLegacy {
    TxLegacy {
      to: TxKind::Call(self.address),
      input: abi::escapeCall::new((Address::from(coin),)).abi_encode().into(),
      ..Default::default()
    }
  }

  /// Fetch the `InInstruction`s for the Router for the specified inclusive range of blocks.
  ///
  /// This includes all `InInstruction` events from the Router and all top-level transfers to the
  /// Router.
  ///
  /// This is not guaranteed to return them in any order.
  pub async fn in_instructions_unordered(
    &self,
    blocks: RangeInclusive<u64>,
    allowed_erc20s: &HashSet<Address>,
  ) -> Result<Vec<InInstruction>, RpcError<TransportErrorKind>> {
    // The InInstruction events for this block
    let in_instruction_logs = {
      // https://github.com/rust-lang/rust/issues/27186
      let filter = Filter::new().select(blocks.clone()).address(self.address);
      let filter = filter.event_signature(InInstructionEvent::SIGNATURE_HASH);
      self.provider.get_logs(&filter).await?
    };

    // Define the Vec for the result now that we have the logs as a size hint
    let mut in_instructions = Vec::with_capacity(in_instruction_logs.len());

    // Handle the top-level transfers for this block
    let mut justifying_erc20_transfer_logs = HashSet::new();
    let erc20_transfer_logs = {
      let mut transfers = FuturesUnordered::new();
      for erc20 in allowed_erc20s {
        transfers.push({
          // https://github.com/rust-lang/rust/issues/27186
          let blocks: RangeInclusive<u64> = blocks.clone();
          async move {
            let transfers =
              Erc20::top_level_transfers_unordered(&self.provider, blocks, *erc20, self.address)
                .await;
            (erc20, transfers)
          }
        });
      }

      let mut logs = HashMap::with_capacity(allowed_erc20s.len());
      while let Some((token, transfers)) = transfers.next().await {
        let TopLevelTransfers { logs: token_logs, transfers } = transfers?;
        logs.insert(token, token_logs);
        // Map the top-level transfer to an InInstruction
        for transfer in transfers {
          let TopLevelTransfer { id, transaction_hash, from, amount, data } = transfer;
          justifying_erc20_transfer_logs.insert(transfer.id);
          let in_instruction =
            InInstruction { id, transaction_hash, from, coin: Coin::Erc20(*token), amount, data };
          in_instructions.push(in_instruction);
        }
      }
      logs
    };

    // Now handle the InInstruction events
    for log in in_instruction_logs {
      // Double check the address which emitted this log
      if log.address() != self.address {
        Err(TransportErrorKind::Custom(
          "node returned a log from a different address than requested".to_string().into(),
        ))?;
      }
      // Double check this is a InInstruction log
      if log.topics().first() != Some(&InInstructionEvent::SIGNATURE_HASH) {
        continue;
      }

      let log_index = |log: &Log| -> Result<LogIndex, TransportErrorKind> {
        Ok(LogIndex {
          block_hash: log
            .block_hash
            .ok_or_else(|| {
              TransportErrorKind::Custom("log didn't have its block hash set".to_string().into())
            })?
            .into(),
          index_within_block: log.log_index.ok_or_else(|| {
            TransportErrorKind::Custom("log didn't have its index set".to_string().into())
          })?,
        })
      };

      let id = log_index(&log)?;

      let transaction_hash = log.transaction_hash.ok_or_else(|| {
        TransportErrorKind::Custom("log didn't have its transaction hash set".to_string().into())
      })?;
      let transaction_hash = *transaction_hash;

      let log = log
        .log_decode::<InInstructionEvent>()
        .map_err(|e| {
          TransportErrorKind::Custom(
            format!("filtered to InInstructionEvent yet couldn't decode log: {e:?}").into(),
          )
        })?
        .inner
        .data;

      let coin = Coin::from(log.coin);

      let in_instruction = InInstruction {
        id,
        transaction_hash,
        from: log.from,
        coin,
        amount: log.amount,
        data: log.instruction.as_ref().to_vec(),
      };

      match coin {
        Coin::Ether => {}
        Coin::Erc20(token) => {
          // Check this is an allowed token
          if !allowed_erc20s.contains(&token) {
            continue;
          }

          /*
            We check that for all InInstructions for ERC20s emitted, a corresponding transfer
            occurred.

            We don't do this for ETH as it'd require tracing the transaction, which is non-trivial.
            It also isn't necessary as all of this is solely defense in depth.
          */
          let mut justified = false;
          // These logs are returned from `top_level_transfers_unordered` and we don't require any
          // ordering of them
          for log in erc20_transfer_logs[&token].get(&transaction_hash).unwrap_or(&vec![]) {
            let log_index = log_index(log)?;

            // Ensure we didn't already use this transfer to justify a distinct InInstruction
            if justifying_erc20_transfer_logs.contains(&log_index) {
              continue;
            }

            // Check if this log is from the token we expected to be transferred
            if log.address() != Address::from(in_instruction.coin) {
              continue;
            }
            // Check if this is a transfer log
            if log.topics().first() != Some(&Transfer::SIGNATURE_HASH) {
              continue;
            }
            let Ok(transfer) = Transfer::decode_log(&log.inner.clone(), true) else { continue };
            // Check if this aligns with the InInstruction
            if (transfer.from == in_instruction.from) &&
              (transfer.to == self.address) &&
              (transfer.value == in_instruction.amount)
            {
              justifying_erc20_transfer_logs.insert(log_index);
              justified = true;
              break;
            }
          }
          if !justified {
            // This is an exploit, a non-conforming ERC20, or an invalid connection
            Err(TransportErrorKind::Custom(
              "ERC20 InInstruction with no matching transfer log".to_string().into(),
            ))?;
          }
        }
      }
      in_instructions.push(in_instruction);
    }

    Ok(in_instructions)
  }

  /// Fetch the executed actions for the specified range of blocks.
  pub async fn executed(
    &self,
    blocks: RangeInclusive<u64>,
  ) -> Result<Vec<Executed>, RpcError<TransportErrorKind>> {
    fn decode<E: SolEvent>(log: &Log) -> Result<E, RpcError<TransportErrorKind>> {
      Ok(
        log
          .log_decode::<E>()
          .map_err(|e| {
            TransportErrorKind::Custom(
              format!("filtered to event yet couldn't decode log: {e:?}").into(),
            )
          })?
          .inner
          .data,
      )
    }

    let filter = Filter::new().select(blocks).address(self.address);
    let mut logs = self.provider.get_logs(&filter).await?;
    logs.sort_by_key(|log| (log.block_number, log.log_index));

    let mut res = vec![];
    for log in logs {
      // Double check the address which emitted this log
      if log.address() != self.address {
        Err(TransportErrorKind::Custom(
          "node returned a log from a different address than requested".to_string().into(),
        ))?;
      }

      match log.topics().first() {
        Some(&NextSeraiKeySetEvent::SIGNATURE_HASH) => {
          let event = decode::<NextSeraiKeySetEvent>(&log)?;
          res.push(Executed::NextSeraiKeySet {
            nonce: event.nonce.try_into().map_err(|e| {
              TransportErrorKind::Custom(format!("failed to convert nonce to u64: {e:?}").into())
            })?,
            key: event.key.into(),
          });
        }
        Some(&SeraiKeyUpdatedEvent::SIGNATURE_HASH) => {
          let event = decode::<SeraiKeyUpdatedEvent>(&log)?;
          res.push(Executed::SeraiKeyUpdated {
            nonce: event.nonce.try_into().map_err(|e| {
              TransportErrorKind::Custom(format!("failed to convert nonce to u64: {e:?}").into())
            })?,
            key: event.key.into(),
          });
        }
        Some(&BatchEvent::SIGNATURE_HASH) => {
          let event = decode::<BatchEvent>(&log)?;
          res.push(Executed::Batch {
            nonce: event.nonce.try_into().map_err(|e| {
              TransportErrorKind::Custom(format!("failed to convert nonce to u64: {e:?}").into())
            })?,
            message_hash: event.messageHash.into(),
            results: {
              let results_len = usize::try_from(event.resultsLength).map_err(|e| {
                TransportErrorKind::Custom(
                  format!("failed to convert resultsLength to usize: {e:?}").into(),
                )
              })?;
              if results_len.div_ceil(8) != event.results.len() {
                Err(TransportErrorKind::Custom(
                  "resultsLength didn't align with results length".to_string().into(),
                ))?;
              }
              let mut results = Vec::with_capacity(results_len);
              for b in 0 .. results_len {
                let byte = event.results[b / 8];
                results.push(((byte >> (b % 8)) & 1) == 1);
              }
              results
            },
          });
        }
        Some(&EscapeHatchEvent::SIGNATURE_HASH) => {
          let event = decode::<EscapeHatchEvent>(&log)?;
          res.push(Executed::EscapeHatch {
            nonce: event.nonce.try_into().map_err(|e| {
              TransportErrorKind::Custom(format!("failed to convert nonce to u64: {e:?}").into())
            })?,
            escape_to: event.escapeTo,
          });
        }
        Some(&InInstructionEvent::SIGNATURE_HASH | &EscapedEvent::SIGNATURE_HASH) => {}
        unrecognized => Err(TransportErrorKind::Custom(
          format!("unrecognized event yielded by the Router: {:?}", unrecognized.map(hex::encode))
            .into(),
        ))?,
      }
    }

    Ok(res)
  }

  /// Fetch the `Escape`s from the smart contract through the escape hatch.
  pub async fn escapes(
    &self,
    blocks: RangeInclusive<u64>,
  ) -> Result<Vec<Escape>, RpcError<TransportErrorKind>> {
    let filter = Filter::new().select(blocks).address(self.address);
    let mut logs =
      self.provider.get_logs(&filter.event_signature(EscapedEvent::SIGNATURE_HASH)).await?;
    logs.sort_by_key(|log| (log.block_number, log.log_index));

    let mut res = vec![];
    for log in logs {
      // Double check the address which emitted this log
      if log.address() != self.address {
        Err(TransportErrorKind::Custom(
          "node returned a log from a different address than requested".to_string().into(),
        ))?;
      }
      // Double check the topic
      if log.topics().first() != Some(&EscapedEvent::SIGNATURE_HASH) {
        Err(TransportErrorKind::Custom(
          "node returned a log for a different topic than filtered to".to_string().into(),
        ))?;
      }

      let log = log
        .log_decode::<EscapedEvent>()
        .map_err(|e| {
          TransportErrorKind::Custom(
            format!("filtered to event yet couldn't decode log: {e:?}").into(),
          )
        })?
        .inner
        .data;
      res.push(Escape { coin: Coin::from(log.coin), amount: log.amount });
    }

    Ok(res)
  }

  async fn fetch_key(
    &self,
    block: BlockId,
    call: Vec<u8>,
  ) -> Result<Option<PublicKey>, RpcError<TransportErrorKind>> {
    let call =
      TransactionRequest::default().to(self.address).input(TransactionInput::new(call.into()));
    let bytes = self.provider.call(&call).block(block).await?;
    // This is fine as both key calls share a return type
    let res = abi::nextSeraiKeyCall::abi_decode_returns(&bytes, true)
      .map_err(|e| TransportErrorKind::Custom(format!("failed to decode key: {e:?}").into()))?;
    let eth_repr = <[u8; 32]>::from(res._0);
    Ok(if eth_repr == [0; 32] {
      None
    } else {
      Some(PublicKey::from_eth_repr(eth_repr).ok_or_else(|| {
        TransportErrorKind::Custom("invalid key set on router".to_string().into())
      })?)
    })
  }

  /// Fetch the next key for Serai's Ethereum validators
  pub async fn next_key(
    &self,
    block: BlockId,
  ) -> Result<Option<PublicKey>, RpcError<TransportErrorKind>> {
    self.fetch_key(block, abi::nextSeraiKeyCall::new(()).abi_encode()).await
  }

  /// Fetch the current key for Serai's Ethereum validators
  pub async fn key(
    &self,
    block: BlockId,
  ) -> Result<Option<PublicKey>, RpcError<TransportErrorKind>> {
    self.fetch_key(block, abi::seraiKeyCall::new(()).abi_encode()).await
  }

  /// Fetch the nonce of the next action to execute
  pub async fn next_nonce(&self, block: BlockId) -> Result<u64, RpcError<TransportErrorKind>> {
    let call = TransactionRequest::default()
      .to(self.address)
      .input(TransactionInput::new(abi::nextNonceCall::new(()).abi_encode().into()));
    let bytes = self.provider.call(&call).block(block).await?;
    let res = abi::nextNonceCall::abi_decode_returns(&bytes, true)
      .map_err(|e| TransportErrorKind::Custom(format!("failed to decode nonce: {e:?}").into()))?;
    Ok(u64::try_from(res._0).map_err(|_| {
      TransportErrorKind::Custom("nonce returned exceeded 2**64".to_string().into())
    })?)
  }

  /// Fetch the address the escape hatch was set to
  pub async fn escaped_to(
    &self,
    block: BlockId,
  ) -> Result<Option<Address>, RpcError<TransportErrorKind>> {
    let call = TransactionRequest::default()
      .to(self.address)
      .input(TransactionInput::new(abi::escapedToCall::new(()).abi_encode().into()));
    let bytes = self.provider.call(&call).block(block).await?;
    let res = abi::escapedToCall::abi_decode_returns(&bytes, true).map_err(|e| {
      TransportErrorKind::Custom(format!("failed to decode the address escaped to: {e:?}").into())
    })?;
    Ok(if res._0 == Address([0; 20].into()) { None } else { Some(res._0) })
  }
}
