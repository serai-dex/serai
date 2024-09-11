use ciphersuite::{Ciphersuite, Secp256k1};

use bitcoin_serai::{
  bitcoin::ScriptBuf,
  wallet::{TransactionError, SignableTransaction as BSignableTransaction, p2tr_script_buf},
};

use serai_client::{
  primitives::{Coin, Amount},
  networks::bitcoin::Address,
};

use primitives::{OutputType, ReceivedOutput, Payment};
use scanner::{KeyFor, AddressFor, OutputFor, BlockFor};
use utxo_scheduler::{PlannedTransaction, TransactionPlanner};
use transaction_chaining_scheduler::{EffectedReceivedOutputs, Scheduler as GenericScheduler};

use crate::{
  scan::{offsets_for_key, scanner},
  output::Output,
  transaction::{SignableTransaction, Eventuality},
  scanner_feed::Rpc,
};

fn address_from_serai_key(key: <Secp256k1 as Ciphersuite>::G, kind: OutputType) -> Address {
  let offset = <Secp256k1 as Ciphersuite>::G::GENERATOR * offsets_for_key(key)[&kind];
  Address::new(
    p2tr_script_buf(key + offset)
      .expect("creating address from Serai key which wasn't properly tweaked"),
  )
  .expect("couldn't create Serai-representable address for P2TR script")
}

fn signable_transaction(
  fee_per_vbyte: u64,
  inputs: Vec<OutputFor<Rpc>>,
  payments: Vec<Payment<AddressFor<Rpc>>>,
  change: Option<KeyFor<Rpc>>,
) -> Result<(SignableTransaction, BSignableTransaction), TransactionError> {
  assert!(inputs.len() < Planner::MAX_INPUTS);
  assert!((payments.len() + usize::from(u8::from(change.is_some()))) < Planner::MAX_OUTPUTS);

  let inputs = inputs.into_iter().map(|input| input.output).collect::<Vec<_>>();
  let payments = payments
    .into_iter()
    .map(|payment| {
      (payment.address().clone(), {
        let balance = payment.balance();
        assert_eq!(balance.coin, Coin::Bitcoin);
        balance.amount.0
      })
    })
    .collect::<Vec<_>>();
  let change = change.map(Planner::change_address);

  // TODO: ACP output
  BSignableTransaction::new(
    inputs.clone(),
    &payments
      .iter()
      .cloned()
      .map(|(address, amount)| (ScriptBuf::from(address), amount))
      .collect::<Vec<_>>(),
    change.clone().map(ScriptBuf::from),
    None,
    fee_per_vbyte,
  )
  .map(|bst| (SignableTransaction { inputs, payments, change, fee_per_vbyte }, bst))
}

pub(crate) struct Planner;
impl TransactionPlanner<Rpc, EffectedReceivedOutputs<Rpc>> for Planner {
  type FeeRate = u64;

  type SignableTransaction = SignableTransaction;

  /*
    Bitcoin has a max weight of 400,000 (MAX_STANDARD_TX_WEIGHT).

    A non-SegWit TX will have 4 weight units per byte, leaving a max size of 100,000 bytes. While
    our inputs are entirely SegWit, such fine tuning is not necessary and could create issues in
    the future (if the size decreases or we misevaluate it). It also offers a minimal amount of
    benefit when we are able to logarithmically accumulate inputs/fulfill payments.

    For 128-byte inputs (36-byte output specification, 64-byte signature, whatever overhead) and
    64-byte outputs (40-byte script, 8-byte amount, whatever overhead), they together take up 192
    bytes.

    100,000 / 192 = 520
    520 * 192 leaves 160 bytes of overhead for the transaction structure itself.
  */
  const MAX_INPUTS: usize = 520;
  // We always reserve one output to create an anyone-can-spend output enabling anyone to use CPFP
  // to unstick any transactions which had too low of a fee.
  const MAX_OUTPUTS: usize = 519;

  fn fee_rate(block: &BlockFor<Rpc>, coin: Coin) -> Self::FeeRate {
    assert_eq!(coin, Coin::Bitcoin);
    // TODO
    1
  }

  fn branch_address(key: KeyFor<Rpc>) -> AddressFor<Rpc> {
    address_from_serai_key(key, OutputType::Branch)
  }
  fn change_address(key: KeyFor<Rpc>) -> AddressFor<Rpc> {
    address_from_serai_key(key, OutputType::Change)
  }
  fn forwarding_address(key: KeyFor<Rpc>) -> AddressFor<Rpc> {
    address_from_serai_key(key, OutputType::Forwarded)
  }

  fn calculate_fee(
    fee_rate: Self::FeeRate,
    inputs: Vec<OutputFor<Rpc>>,
    payments: Vec<Payment<AddressFor<Rpc>>>,
    change: Option<KeyFor<Rpc>>,
  ) -> Amount {
    match signable_transaction(fee_rate, inputs, payments, change) {
      Ok(tx) => Amount(tx.1.needed_fee()),
      Err(
        TransactionError::NoInputs | TransactionError::NoOutputs | TransactionError::DustPayment,
      ) => panic!("malformed arguments to calculate_fee"),
      // No data, we have a minimum fee rate, we checked the amount of inputs/outputs
      Err(
        TransactionError::TooMuchData |
        TransactionError::TooLowFee |
        TransactionError::TooLargeTransaction,
      ) => unreachable!(),
      Err(TransactionError::NotEnoughFunds { fee, .. }) => Amount(fee),
    }
  }

  fn plan(
    fee_rate: Self::FeeRate,
    inputs: Vec<OutputFor<Rpc>>,
    payments: Vec<Payment<AddressFor<Rpc>>>,
    change: Option<KeyFor<Rpc>>,
  ) -> PlannedTransaction<Rpc, Self::SignableTransaction, EffectedReceivedOutputs<Rpc>> {
    let key = inputs.first().unwrap().key();
    for input in &inputs {
      assert_eq!(key, input.key());
    }

    let singular_spent_output = (inputs.len() == 1).then(|| inputs[0].id());
    match signable_transaction(fee_rate, inputs, payments, change) {
      Ok(tx) => PlannedTransaction {
        signable: tx.0,
        eventuality: Eventuality { txid: tx.1.txid(), singular_spent_output },
        auxilliary: EffectedReceivedOutputs({
          let tx = tx.1.transaction();
          let scanner = scanner(key);

          let mut res = vec![];
          for output in scanner.scan_transaction(tx) {
            res.push(Output::new(key, tx, output));
          }
          res
        }),
      },
      Err(
        TransactionError::NoInputs | TransactionError::NoOutputs | TransactionError::DustPayment,
      ) => panic!("malformed arguments to plan"),
      // No data, we have a minimum fee rate, we checked the amount of inputs/outputs
      Err(
        TransactionError::TooMuchData |
        TransactionError::TooLowFee |
        TransactionError::TooLargeTransaction,
      ) => unreachable!(),
      Err(TransactionError::NotEnoughFunds { .. }) => {
        panic!("plan called for a transaction without enough funds")
      }
    }
  }
}

pub(crate) type Scheduler = GenericScheduler<Rpc, Planner>;
