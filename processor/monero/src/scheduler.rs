use ciphersuite::{Ciphersuite, Secp256k1};

use bitcoin_serai::{
  bitcoin::ScriptBuf,
  wallet::{TransactionError, SignableTransaction as BSignableTransaction, p2tr_script_buf},
};

use serai_client::{
  primitives::{Coin, Amount},
  networks::bitcoin::Address,
};

use serai_db::Db;
use primitives::{OutputType, ReceivedOutput, Payment};
use scanner::{KeyFor, AddressFor, OutputFor, BlockFor};
use utxo_scheduler::{PlannedTransaction, TransactionPlanner};

use crate::{
  scan::{offsets_for_key, scanner},
  output::Output,
  transaction::{SignableTransaction, Eventuality},
  rpc::Rpc,
};

fn address_from_serai_key(key: <Secp256k1 as Ciphersuite>::G, kind: OutputType) -> Address {
  let offset = <Secp256k1 as Ciphersuite>::G::GENERATOR * offsets_for_key(key)[&kind];
  Address::new(
    p2tr_script_buf(key + offset)
      .expect("creating address from Serai key which wasn't properly tweaked"),
  )
  .expect("couldn't create Serai-representable address for P2TR script")
}

fn signable_transaction<D: Db>(
  fee_per_vbyte: u64,
  inputs: Vec<OutputFor<Rpc<D>>>,
  payments: Vec<Payment<AddressFor<Rpc<D>>>>,
  change: Option<KeyFor<Rpc<D>>>,
) -> Result<(SignableTransaction, BSignableTransaction), TransactionError> {
  assert!(
    inputs.len() <
      <Planner as TransactionPlanner<Rpc<D>, ()>>::MAX_INPUTS
  );
  assert!(
    (payments.len() + usize::from(u8::from(change.is_some()))) <
      <Planner as TransactionPlanner<Rpc<D>, ()>>::MAX_OUTPUTS
  );

  let inputs = inputs.into_iter().map(|input| input.output).collect::<Vec<_>>();

  let mut payments = payments
    .into_iter()
    .map(|payment| {
      (payment.address().clone(), {
        let balance = payment.balance();
        assert_eq!(balance.coin, Coin::Bitcoin);
        balance.amount.0
      })
    })
    .collect::<Vec<_>>();
  /*
    Push a payment to a key with a known private key which anyone can spend. If this transaction
    gets stuck, this lets anyone create a child transaction spending this output, raising the fee,
    getting the transaction unstuck (via CPFP).
  */
  payments.push((
    // The generator is even so this is valid
    Address::new(p2tr_script_buf(<Secp256k1 as Ciphersuite>::G::GENERATOR).unwrap()).unwrap(),
    // This uses the minimum output value allowed, as defined as a constant in bitcoin-serai
    // TODO: Add a test for this comparing to bitcoin's `minimal_non_dust`
    bitcoin_serai::wallet::DUST,
  ));

  let change = change
    .map(<Planner as TransactionPlanner<Rpc<D>, ()>>::change_address);

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
impl TransactionPlanner<Rpc, ()> for Planner {
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

  fn fee_rate(block: &BlockFor<Rpc<D>>, coin: Coin) -> Self::FeeRate {
    assert_eq!(coin, Coin::Bitcoin);
    // TODO
    1
  }

  fn branch_address(key: KeyFor<Rpc<D>>) -> AddressFor<Rpc<D>> {
    address_from_serai_key(key, OutputType::Branch)
  }
  fn change_address(key: KeyFor<Rpc<D>>) -> AddressFor<Rpc<D>> {
    address_from_serai_key(key, OutputType::Change)
  }
  fn forwarding_address(key: KeyFor<Rpc<D>>) -> AddressFor<Rpc<D>> {
    address_from_serai_key(key, OutputType::Forwarded)
  }

  fn calculate_fee(
    fee_rate: Self::FeeRate,
    inputs: Vec<OutputFor<Rpc<D>>>,
    payments: Vec<Payment<AddressFor<Rpc<D>>>>,
    change: Option<KeyFor<Rpc<D>>>,
  ) -> Amount {
    match signable_transaction::<D>(fee_rate, inputs, payments, change) {
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
    inputs: Vec<OutputFor<Rpc<D>>>,
    payments: Vec<Payment<AddressFor<Rpc<D>>>>,
    change: Option<KeyFor<Rpc<D>>>,
  ) -> PlannedTransaction<Rpc<D>, Self::SignableTransaction, ()> {
    let key = inputs.first().unwrap().key();
    for input in &inputs {
      assert_eq!(key, input.key());
    }

    let singular_spent_output = (inputs.len() == 1).then(|| inputs[0].id());
    match signable_transaction::<D>(fee_rate, inputs.clone(), payments, change) {
      Ok(tx) => PlannedTransaction {
        signable: tx.0,
        eventuality: Eventuality { txid: tx.1.txid(), singular_spent_output },
        auxilliary: (),
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

pub(crate) type Scheduler = utxo_standard_scheduler::Scheduler<Rpc, Planner>;
