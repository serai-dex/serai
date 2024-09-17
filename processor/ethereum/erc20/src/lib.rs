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

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod abi {
  alloy_sol_macro::sol!("contracts/IERC20.sol");
}
use abi::IERC20::{IERC20Calls, Transfer, transferCall, transferFromCall};

/// A top-level ERC20 transfer
#[derive(Clone, Debug)]
pub struct TopLevelErc20Transfer {
  /// The transaction ID which effected this transfer.
  pub id: [u8; 32],
  /// The address which made the transfer.
  pub from: [u8; 20],
  /// The amount transferred.
  pub amount: U256,
  /// The data appended after the call itself.
  pub data: Vec<u8>,
}

/// A view for an ERC20 contract.
#[derive(Clone, Debug)]
pub struct Erc20(Arc<RootProvider<SimpleRequest>>, Address);
impl Erc20 {
  /// Construct a new view of the specified ERC20 contract.
  pub fn new(provider: Arc<RootProvider<SimpleRequest>>, address: [u8; 20]) -> Self {
    Self(provider, Address::from(&address))
  }

  /// Fetch all top-level transfers to the specified ERC20.
  pub async fn top_level_transfers(
    &self,
    block: u64,
    to: [u8; 20],
  ) -> Result<Vec<TopLevelErc20Transfer>, RpcError<TransportErrorKind>> {
    let filter = Filter::new().from_block(block).to_block(block).address(self.1);
    let filter = filter.event_signature(Transfer::SIGNATURE_HASH);
    let mut to_topic = [0; 32];
    to_topic[12 ..].copy_from_slice(&to);
    let filter = filter.topic2(B256::from(to_topic));
    let logs = self.0.get_logs(&filter).await?;

    /*
      A set of all transactions we've handled a transfer from. This handles the edge case where a
      top-level transfer T somehow triggers another transfer T', with equivalent contents, within
      the same transaction. We only want to report one transfer as only one is top-level.
    */
    let mut handled = HashSet::new();

    let mut top_level_transfers = vec![];
    for log in logs {
      // Double check the address which emitted this log
      if log.address() != self.1 {
        Err(TransportErrorKind::Custom(
          "node returned logs for a different address than requested".to_string().into(),
        ))?;
      }

      let tx_id = log.transaction_hash.ok_or_else(|| {
        TransportErrorKind::Custom("log didn't specify its transaction hash".to_string().into())
      })?;
      let tx = self.0.get_transaction_by_hash(tx_id).await?.ok_or_else(|| {
        TransportErrorKind::Custom(
          "node didn't have the transaction which emitted a log it had".to_string().into(),
        )
      })?;

      // If this is a top-level call...
      if tx.to == Some(self.1) {
        // And we recognize the call...
        // Don't validate the encoding as this can't be re-encoded to an identical bytestring due
        // to the InInstruction appended
        if let Ok(call) = IERC20Calls::abi_decode(&tx.input, false) {
          // Extract the top-level call's from/to/value
          let (from, call_to, value) = match call {
            IERC20Calls::transfer(transferCall { to: call_to, value }) => (tx.from, call_to, value),
            IERC20Calls::transferFrom(transferFromCall { from, to: call_to, value }) => {
              (from, call_to, value)
            }
            // Treat any other function selectors as unrecognized
            _ => continue,
          };

          let log = log
            .log_decode::<Transfer>()
            .map_err(|e| {
              TransportErrorKind::Custom(format!("failed to decode Transfer log: {e:?}").into())
            })?
            .inner
            .data;

          // Ensure the top-level transfer is equivalent, and this presumably isn't a log for an
          // internal transfer
          if (log.from != from) || (call_to != to) || (value != log.value) {
            continue;
          }

          // Now that the top-level transfer is confirmed to be equivalent to the log, ensure it's
          // the only log we handle
          if handled.contains(&tx_id) {
            continue;
          }
          handled.insert(tx_id);

          // Read the data appended after
          let encoded = call.abi_encode();
          let data = tx.input.as_ref()[encoded.len() ..].to_vec();

          // Push the transfer
          top_level_transfers.push(TopLevelErc20Transfer {
            // Since we'll only handle one log for this TX, set the ID to the TX ID
            id: *tx_id,
            from: *log.from.0,
            amount: log.value,
            data,
          });
        }
      }
    }
    Ok(top_level_transfers)
  }
}
