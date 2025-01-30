#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::ops::RangeInclusive;
use std::collections::HashMap;

use alloy_core::primitives::{Address, U256};

use alloy_sol_types::{SolInterface, SolEvent};

use alloy_rpc_types_eth::{Log, Filter, TransactionTrait};
use alloy_transport::{TransportErrorKind, RpcError};
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

use ethereum_primitives::LogIndex;

use futures_util::stream::{StreamExt, FuturesUnordered};

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(missing_docs)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod abi {
  alloy_sol_macro::sol!("contracts/IERC20.sol");
}
use abi::IERC20::{IERC20Calls, transferCall, transferFromCall};
use abi::SeraiIERC20::SeraiIERC20Calls;
pub use abi::IERC20::Transfer;
pub use abi::SeraiIERC20::{
  transferWithInInstruction01BB244A8ACall as transferWithInInstructionCall,
  transferFromWithInInstruction00081948E0Call as transferFromWithInInstructionCall,
};

#[cfg(test)]
mod tests;

/// A top-level ERC20 transfer
///
/// This does not include `token`, `to` fields. Those are assumed contextual to the creation of
/// this.
#[derive(Clone, Debug)]
pub struct TopLevelTransfer {
  /// The ID of the event for this transfer.
  pub id: LogIndex,
  /// The hash of the transaction which caused this transfer.
  pub transaction_hash: [u8; 32],
  /// The address which made the transfer.
  pub from: Address,
  /// The amount transferred.
  pub amount: U256,
  /// The data appended after the call itself.
  pub data: Vec<u8>,
}

/// The result of `Erc20::top_level_transfers_unordered`.
pub struct TopLevelTransfers {
  /// Every `Transfer` log of the contextual ERC20 to the contextual account, indexed by
  /// their transaction.
  ///
  /// The ERC20/account is labelled contextual as it isn't directly named here. Instead, they're
  /// assumed contextual to how this was created.
  pub logs: HashMap<[u8; 32], Vec<Log>>,
  /// All of the top-level transfers of the contextual ERC20 to the contextual account.
  ///
  /// The ERC20/account is labelled contextual as it isn't directly named here. Instead, they're
  /// assumed contextual to how this was created.
  pub transfers: Vec<TopLevelTransfer>,
}

/// A view for an ERC20 contract.
#[derive(Clone, Debug)]
pub struct Erc20;
impl Erc20 {
  /// The filter for transfer logs of the specified ERC20, to the specified recipient.
  fn transfer_filter(blocks: RangeInclusive<u64>, erc20: Address, to: Address) -> Filter {
    let filter = Filter::new().select(blocks);
    filter.address(erc20).event_signature(Transfer::SIGNATURE_HASH).topic2(to.into_word())
  }

  /// Yield the top-level transfer for the specified transaction (if one exists).
  ///
  /// The passed-in logs MUST be the logs for this transaction. The logs MUST be filtered to the
  /// `Transfer` events of the intended token and the intended `to` transferred to. These
  /// properties are completely unchecked and assumed to be the case.
  ///
  /// This does NOT yield THE top-level transfer. If multiple `Transfer` events have identical
  /// structure to the top-level transfer call, the first `Transfer` event present in the logs is
  /// considered the top-level transfer.
  // Yielding THE top-level transfer would require tracing the transaction execution and isn't
  // worth the effort.
  async fn top_level_transfer(
    provider: &RootProvider<SimpleRequest>,
    erc20: Address,
    transaction_hash: [u8; 32],
    transfer_logs: &[Log],
  ) -> Result<Option<TopLevelTransfer>, RpcError<TransportErrorKind>> {
    // Fetch the transaction
    let transaction =
      provider.get_transaction_by_hash(transaction_hash.into()).await?.ok_or_else(|| {
        TransportErrorKind::Custom(
          "node didn't have the transaction which emitted a log it had".to_string().into(),
        )
      })?;

    // If this transaction didn't call this ERC20 at a top-level, return
    if transaction.inner.to() != Some(erc20) {
      return Ok(None);
    }

    // Don't validate the encoding as this can't be re-encoded to an identical bytestring due
    // to the additional data appended after the call itself
    let Ok(call) = IERC20Calls::abi_decode(transaction.inner.input(), false) else {
      return Ok(None);
    };

    // Extract the top-level call's from/to/value
    let (from, to, value) = match call {
      IERC20Calls::transfer(transferCall { to, value }) => (transaction.from, to, value),
      IERC20Calls::transferFrom(transferFromCall { from, to, value }) => (from, to, value),
      // Treat any other function selectors as unrecognized
      _ => return Ok(None),
    };

    // Find the log for this top-level transfer
    for log in transfer_logs {
      // Since the caller is responsible for filtering these to `Transfer` events, we can assume
      // this is a non-compliant ERC20 or an error with the logs fetched. We assume ERC20
      // compliance here, making this an RPC error
      let log = log.log_decode::<Transfer>().map_err(|_| {
        TransportErrorKind::Custom("log didn't include a valid transfer event".to_string().into())
      })?;

      let block_hash = log.block_hash.ok_or_else(|| {
        TransportErrorKind::Custom("log didn't have its block hash set".to_string().into())
      })?;
      let log_index = log.log_index.ok_or_else(|| {
        TransportErrorKind::Custom("log didn't have its index set".to_string().into())
      })?;
      let log = log.inner.data;

      // Ensure the top-level transfer is equivalent to the transfer this log represents
      if !((log.from == from) && (log.to == to) && (log.value == value)) {
        continue;
      }

      // Read the data appended after
      let data = if let Ok(call) = SeraiIERC20Calls::abi_decode(transaction.inner.input(), true) {
        match call {
          SeraiIERC20Calls::transferWithInInstruction01BB244A8A(
            transferWithInInstructionCall { inInstruction, .. },
          ) |
          SeraiIERC20Calls::transferFromWithInInstruction00081948E0(
            transferFromWithInInstructionCall { inInstruction, .. },
          ) => Vec::from(inInstruction),
        }
      } else {
        // If there was no additional data appended, use an empty Vec (which has no data)
        // This has a slight information loss in that it's None -> Some(vec![]), but it's fine
        vec![]
      };

      return Ok(Some(TopLevelTransfer {
        id: LogIndex { block_hash: *block_hash, index_within_block: log_index },
        transaction_hash,
        from: log.from,
        amount: log.value,
        data,
      }));
    }

    Ok(None)
  }

  /// Fetch all top-level transfers to the specified address for this token.
  ///
  /// The `transfers` in the result are unordered. The `logs` are sorted by index.
  pub async fn top_level_transfers_unordered(
    provider: &RootProvider<SimpleRequest>,
    blocks: RangeInclusive<u64>,
    erc20: Address,
    to: Address,
  ) -> Result<TopLevelTransfers, RpcError<TransportErrorKind>> {
    let mut logs = {
      // Get all transfers within these blocks
      let logs = provider.get_logs(&Self::transfer_filter(blocks, erc20, to)).await?;

      // The logs, indexed by their transactions
      let mut transaction_logs = HashMap::new();
      // Index the logs by their transactions
      for log in logs {
        // Double check the address which emitted this log
        if log.address() != erc20 {
          Err(TransportErrorKind::Custom(
            "node returned logs for a different address than requested".to_string().into(),
          ))?;
        }
        // Double check the event signature for this log
        if log.topics().first() != Some(&Transfer::SIGNATURE_HASH) {
          Err(TransportErrorKind::Custom(
            "node returned a log for a different topic than filtered to".to_string().into(),
          ))?;
        }
        // Double check the `to` topic
        if log.topics().get(2) != Some(&to.into_word()) {
          Err(TransportErrorKind::Custom(
            "node returned a transfer for a different `to` than filtered to".to_string().into(),
          ))?;
        }

        let tx_id = log
          .transaction_hash
          .ok_or_else(|| {
            TransportErrorKind::Custom("log didn't specify its transaction hash".to_string().into())
          })?
          .0;

        transaction_logs.entry(tx_id).or_insert_with(|| Vec::with_capacity(1)).push(log);
      }

      transaction_logs
    };

    let mut transfers = vec![];
    {
      // Use `FuturesUnordered` so these RPC calls run in parallel
      let mut futures = FuturesUnordered::new();
      for (tx_id, transfer_logs) in &mut logs {
        // Sort the logs to ensure the the earliest logs are first
        transfer_logs.sort_by_key(|log| log.log_index);
        futures.push(Self::top_level_transfer(provider, erc20, *tx_id, transfer_logs));
      }

      while let Some(transfer) = futures.next().await {
        match transfer {
          // Top-level transfer
          Ok(Some(transfer)) => transfers.push(transfer),
          // Not a top-level transfer
          Ok(None) => continue,
          // Failed to get this transaction's information so abort
          Err(e) => Err(e)?,
        }
      }
    }

    Ok(TopLevelTransfers { logs, transfers })
  }
}
