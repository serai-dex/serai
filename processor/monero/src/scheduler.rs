use core::future::Future;

use zeroize::Zeroizing;
use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use ciphersuite::{Ciphersuite, Ed25519};

use monero_wallet::rpc::{FeeRate, RpcError};

use serai_client::{
  primitives::{Coin, Amount},
  networks::monero::Address,
};

use primitives::{OutputType, ReceivedOutput, Payment};
use scanner::{KeyFor, AddressFor, OutputFor, BlockFor};
use utxo_scheduler::{PlannedTransaction, TransactionPlanner};

use monero_wallet::{
  ringct::RctType,
  address::{Network, AddressType, MoneroAddress},
  OutputWithDecoys,
  send::{
    Change, SendError, SignableTransaction as MSignableTransaction, Eventuality as MEventuality,
  },
};

use crate::{
  EXTERNAL_SUBADDRESS, BRANCH_SUBADDRESS, CHANGE_SUBADDRESS, FORWARDED_SUBADDRESS, view_pair,
  transaction::{SignableTransaction, Eventuality},
  rpc::Rpc,
};

fn address_from_serai_key(key: <Ed25519 as Ciphersuite>::G, kind: OutputType) -> Address {
  view_pair(key)
    .address(
      Network::Mainnet,
      Some(match kind {
        OutputType::External => EXTERNAL_SUBADDRESS,
        OutputType::Branch => BRANCH_SUBADDRESS,
        OutputType::Change => CHANGE_SUBADDRESS,
        OutputType::Forwarded => FORWARDED_SUBADDRESS,
      }),
      None,
    )
    .try_into()
    .expect("created address which wasn't representable")
}

async fn signable_transaction(
  rpc: &Rpc,
  reference_block: &BlockFor<Rpc>,
  inputs: Vec<OutputFor<Rpc>>,
  payments: Vec<Payment<AddressFor<Rpc>>>,
  change: Option<KeyFor<Rpc>>,
) -> Result<Result<(SignableTransaction, MSignableTransaction), SendError>, RpcError> {
  assert!(inputs.len() < <Planner as TransactionPlanner<Rpc, ()>>::MAX_INPUTS);
  assert!(
    (payments.len() + usize::from(u8::from(change.is_some()))) <
      <Planner as TransactionPlanner<Rpc, ()>>::MAX_OUTPUTS
  );

  // TODO: Set a sane minimum fee
  const MINIMUM_FEE: u64 = 1_500_000;
  // TODO: Set a fee rate based on the reference block
  let fee_rate = FeeRate::new(MINIMUM_FEE, 10000).unwrap();

  // Determine the RCT proofs to make based off the hard fork
  let rct_type = match reference_block.0.block.header.hardfork_version {
    14 => RctType::ClsagBulletproof,
    15 | 16 => RctType::ClsagBulletproofPlus,
    _ => panic!("Monero hard forked and the processor wasn't updated for it"),
  };

  // We need a unique ID to distinguish this transaction from another transaction with an identical
  // set of payments (as our Eventualities only match over the payments). The output's ID is
  // guaranteed to be unique, making it satisfactory
  let id = inputs.first().unwrap().id().0;

  let mut inputs_actual = Vec::with_capacity(inputs.len());
  for input in inputs {
    inputs_actual.push(
      OutputWithDecoys::fingerprintable_deterministic_new(
        // We need a deterministic RNG here with *some* seed
        // The unique ID means we don't pick some static seed
        // It is a public value, yet that's fine as this is assumed fully transparent
        // It is a reused value (with later code), but that's not an issue. Just an oddity
        &mut ChaCha20Rng::from_seed(id),
        &rpc.rpc,
        match rct_type {
          RctType::ClsagBulletproof => 11,
          RctType::ClsagBulletproofPlus => 16,
          _ => panic!("selecting decoys for an unsupported RctType"),
        },
        reference_block.0.block.number().unwrap() + 1,
        input.0.clone(),
      )
      .await?,
    );
  }
  let inputs = inputs_actual;

  let mut payments = payments
    .into_iter()
    .map(|payment| {
      (MoneroAddress::from(*payment.address()), {
        let balance = payment.balance();
        assert_eq!(balance.coin, Coin::Monero);
        balance.amount.0
      })
    })
    .collect::<Vec<_>>();
  if (payments.len() + usize::from(u8::from(change.is_some()))) == 1 {
    // Monero requires at least two outputs, so add a dummy payment
    payments.push((
      MoneroAddress::new(
        Network::Mainnet,
        AddressType::Legacy,
        <Ed25519 as Ciphersuite>::generator().0,
        <Ed25519 as Ciphersuite>::generator().0,
      ),
      0,
    ));
  }

  let change = if let Some(change) = change {
    Change::guaranteed(view_pair(change), Some(CHANGE_SUBADDRESS))
  } else {
    Change::fingerprintable(None)
  };

  Ok(
    MSignableTransaction::new(
      rct_type,
      Zeroizing::new(id),
      inputs,
      payments,
      change,
      vec![],
      fee_rate,
    )
    .map(|signable| (SignableTransaction { id, signable: signable.clone() }, signable)),
  )
}

#[derive(Clone)]
pub(crate) struct Planner(pub(crate) Rpc);
impl TransactionPlanner<Rpc, ()> for Planner {
  type EphemeralError = RpcError;

  type SignableTransaction = SignableTransaction;

  // wallet2 will not create a transaction larger than 100 KB, and Monero won't relay a transaction
  // larger than 150 KB. This fits within the 100 KB mark to fit in and not poke the bear.
  // Technically, it can be ~124, yet a small bit of buffer is appreciated
  // TODO: Test creating a TX this big
  const MAX_INPUTS: usize = 120;
  const MAX_OUTPUTS: usize = 16;

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
    &self,
    reference_block: &BlockFor<Rpc>,
    inputs: Vec<OutputFor<Rpc>>,
    payments: Vec<Payment<AddressFor<Rpc>>>,
    change: Option<KeyFor<Rpc>>,
  ) -> impl Send + Future<Output = Result<Amount, Self::EphemeralError>> {
    async move {
      Ok(match signable_transaction(&self.0, reference_block, inputs, payments, change).await? {
        Ok(tx) => Amount(tx.1.necessary_fee()),
        Err(SendError::NotEnoughFunds { necessary_fee, .. }) => {
          Amount(necessary_fee.expect("outputs value exceeded inputs value"))
        }
        Err(SendError::UnsupportedRctType) => {
          panic!("tried to use an RctType monero-wallet doesn't support")
        }
        Err(SendError::NoInputs | SendError::NoOutputs | SendError::TooManyOutputs) => {
          panic!("malformed plan passed to calculate_fee")
        }
        Err(SendError::InvalidDecoyQuantity) => panic!("selected the wrong amount of decoys"),
        Err(SendError::NoChange) => {
          panic!("didn't add a dummy payment to satisfy the 2-output minimum")
        }
        Err(SendError::MultiplePaymentIds) => {
          panic!("included multiple payment IDs despite not supporting addresses with payment IDs")
        }
        Err(SendError::TooMuchArbitraryData) => {
          panic!("included too much arbitrary data despite not including any")
        }
        Err(SendError::TooLargeTransaction) => {
          panic!("too large transaction despite MAX_INPUTS/MAX_OUTPUTS")
        }
        Err(
          SendError::WrongPrivateKey |
          SendError::MaliciousSerialization |
          SendError::ClsagError(_) |
          SendError::FrostError(_),
        ) => unreachable!("signing/serialization error when not signing/serializing"),
      })
    }
  }

  fn plan(
    &self,
    reference_block: &BlockFor<Rpc>,
    inputs: Vec<OutputFor<Rpc>>,
    payments: Vec<Payment<AddressFor<Rpc>>>,
    change: Option<KeyFor<Rpc>>,
  ) -> impl Send
       + Future<Output = Result<PlannedTransaction<Rpc, Self::SignableTransaction, ()>, RpcError>>
  {
    let singular_spent_output = (inputs.len() == 1).then(|| inputs[0].id());

    async move {
      Ok(match signable_transaction(&self.0, reference_block, inputs, payments, change).await? {
        Ok(tx) => {
          let id = tx.0.id;
          PlannedTransaction {
            signable: tx.0,
            eventuality: Eventuality {
              id,
              singular_spent_output,
              eventuality: MEventuality::from(tx.1),
            },
            auxilliary: (),
          }
        }
        Err(SendError::NotEnoughFunds { .. }) => panic!("failed to successfully amortize the fee"),
        Err(SendError::UnsupportedRctType) => {
          panic!("tried to use an RctType monero-wallet doesn't support")
        }
        Err(SendError::NoInputs | SendError::NoOutputs | SendError::TooManyOutputs) => {
          panic!("malformed plan passed to calculate_fee")
        }
        Err(SendError::InvalidDecoyQuantity) => panic!("selected the wrong amount of decoys"),
        Err(SendError::NoChange) => {
          panic!("didn't add a dummy payment to satisfy the 2-output minimum")
        }
        Err(SendError::MultiplePaymentIds) => {
          panic!("included multiple payment IDs despite not supporting addresses with payment IDs")
        }
        Err(SendError::TooMuchArbitraryData) => {
          panic!("included too much arbitrary data despite not including any")
        }
        Err(SendError::TooLargeTransaction) => {
          panic!("too large transaction despite MAX_INPUTS/MAX_OUTPUTS")
        }
        Err(
          SendError::WrongPrivateKey |
          SendError::MaliciousSerialization |
          SendError::ClsagError(_) |
          SendError::FrostError(_),
        ) => unreachable!("signing/serialization error when not signing/serializing"),
      })
    }
  }
}

pub(crate) type Scheduler = utxo_standard_scheduler::Scheduler<Rpc, Planner>;
