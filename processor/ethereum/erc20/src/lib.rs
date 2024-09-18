#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::{sync::Arc, collections::HashSet};

use alloy_core::primitives::{Address, B256, U256};

use alloy_sol_types::{SolInterface, SolEvent};

use alloy_rpc_types_eth::Filter;
use alloy_transport::{TransportErrorKind, RpcError};
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

use tokio::task::JoinSet;

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod abi {
  alloy_sol_macro::sol!("contracts/IERC20.sol");
}
use abi::IERC20::{IERC20Calls, transferCall, transferFromCall};
pub use abi::IERC20::Transfer;

/// A top-level ERC20 transfer
#[derive(Clone, Debug)]
pub struct TopLevelTransfer {
  /// The transaction ID which effected this transfer.
  pub id: [u8; 32],
  /// The address which made the transfer.
  pub from: [u8; 20],
  /// The amount transferred.
  pub amount: U256,
  /// The data appended after the call itself.
  pub data: Vec<u8>,
}

/// A transaction with a top-level transfer, matched to the log index of the transfer.
pub struct MatchedTopLevelTransfer {
  /// The transfer.
  pub transfer: TopLevelTransfer,
  /// The log index of the transfer.
  pub log_index: u64,
}

/// A view for an ERC20 contract.
#[derive(Clone, Debug)]
pub struct Erc20(Arc<RootProvider<SimpleRequest>>, Address);
impl Erc20 {
  /// Construct a new view of the specified ERC20 contract.
  pub fn new(provider: Arc<RootProvider<SimpleRequest>>, address: [u8; 20]) -> Self {
    Self(provider, Address::from(&address))
  }

  /// Match a transaction for its top-level transfer to the specified address (if one exists).
  pub async fn match_top_level_transfer(
    provider: impl AsRef<RootProvider<SimpleRequest>>,
    transaction_id: B256,
    to: Address,
  ) -> Result<Option<MatchedTopLevelTransfer>, RpcError<TransportErrorKind>> {
    // Fetch the transaction
    let transaction =
      provider.as_ref().get_transaction_by_hash(transaction_id).await?.ok_or_else(|| {
        TransportErrorKind::Custom(
          "node didn't have the transaction which emitted a log it had".to_string().into(),
        )
      })?;

    // If this is a top-level call...
    // Don't validate the encoding as this can't be re-encoded to an identical bytestring due
    // to the `InInstruction` appended after the call itself
    if let Ok(call) = IERC20Calls::abi_decode(&transaction.input, false) {
      // Extract the top-level call's from/to/value
      let (from, call_to, value) = match call {
        IERC20Calls::transfer(transferCall { to, value }) => (transaction.from, to, value),
        IERC20Calls::transferFrom(transferFromCall { from, to, value }) => (from, to, value),
        // Treat any other function selectors as unrecognized
        _ => return Ok(None),
      };
      // If this isn't a transfer to the expected address, return None
      if call_to != to {
        return Ok(None);
      }

      // Fetch the transaction's logs
      let receipt =
        provider.as_ref().get_transaction_receipt(transaction_id).await?.ok_or_else(|| {
          TransportErrorKind::Custom(
            "node didn't have receipt for a transaction we were matching for a top-level transfer"
              .to_string()
              .into(),
          )
        })?;

      // Find the log for this transfer
      for log in receipt.inner.logs() {
        // If this log was emitted by a different contract, continue
        if Some(log.address()) != transaction.to {
          continue;
        }

        // Check if this is actually a transfer log
        // https://github.com/alloy-rs/core/issues/589
        if log.topics().first() != Some(&Transfer::SIGNATURE_HASH) {
          continue;
        }

        let log_index = log.log_index.ok_or_else(|| {
          TransportErrorKind::Custom("log didn't have its index set".to_string().into())
        })?;
        let log = log
          .log_decode::<Transfer>()
          .map_err(|e| {
            TransportErrorKind::Custom(format!("failed to decode Transfer log: {e:?}").into())
          })?
          .inner
          .data;

        // Ensure the top-level transfer is equivalent to the transfer this log represents. Since
        // we can't find the exact top-level transfer without tracing the call, we just rule the
        // first equivalent transfer as THE top-level transfer
        if !((log.from == from) && (log.to == to) && (log.value == value)) {
          continue;
        }

        // Read the data appended after
        let encoded = call.abi_encode();
        let data = transaction.input.as_ref()[encoded.len() ..].to_vec();

        return Ok(Some(MatchedTopLevelTransfer {
          transfer: TopLevelTransfer {
            // Since there's only one top-level transfer per TX, set the ID to the TX ID
            id: *transaction_id,
            from: *log.from.0,
            amount: log.value,
            data,
          },
          log_index,
        }));
      }
    }

    Ok(None)
  }

  /// Fetch all top-level transfers to the specified address.
  ///
  /// The result of this function is unordered.
  pub async fn top_level_transfers(
    &self,
    block: u64,
    to: Address,
  ) -> Result<Vec<TopLevelTransfer>, RpcError<TransportErrorKind>> {
    // Get all transfers within this block
    let filter = Filter::new().from_block(block).to_block(block).address(self.1);
    let filter = filter.event_signature(Transfer::SIGNATURE_HASH);
    let mut to_topic = [0; 32];
    to_topic[12 ..].copy_from_slice(to.as_ref());
    let filter = filter.topic2(B256::from(to_topic));
    let logs = self.0.get_logs(&filter).await?;

    // These logs are for all transactions which performed any transfer
    // We now check each transaction for having a top-level transfer to the specified address
    let tx_ids = logs
      .into_iter()
      .map(|log| {
        // Double check the address which emitted this log
        if log.address() != self.1 {
          Err(TransportErrorKind::Custom(
            "node returned logs for a different address than requested".to_string().into(),
          ))?;
        }

        log.transaction_hash.ok_or_else(|| {
          TransportErrorKind::Custom("log didn't specify its transaction hash".to_string().into())
        })
      })
      .collect::<Result<HashSet<_>, _>>()?;

    let mut join_set = JoinSet::new();
    for tx_id in tx_ids {
      join_set.spawn(Self::match_top_level_transfer(self.0.clone(), tx_id, to));
    }

    let mut top_level_transfers = vec![];
    while let Some(top_level_transfer) = join_set.join_next().await {
      // This is an error if a task panics or aborts
      // Panicking on a task panic is desired behavior, and we haven't aborted any tasks
      match top_level_transfer.unwrap() {
        // Top-level transfer
        Ok(Some(top_level_transfer)) => top_level_transfers.push(top_level_transfer.transfer),
        // Not a top-level transfer
        Ok(None) => continue,
        // Failed to get this transaction's information so abort
        Err(e) => {
          join_set.abort_all();
          Err(e)?
        }
      }
    }

    Ok(top_level_transfers)
  }
}
