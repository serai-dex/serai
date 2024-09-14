use serai_client::primitives::{NetworkId, Balance};

use ethereum_serai::{alloy::primitives::U256, router::PublicKey, machine::*};

use primitives::Payment;
use scanner::{KeyFor, AddressFor, EventualityFor};

use crate::{
  transaction::{SignableTransaction, Eventuality},
  rpc::Rpc,
};

fn balance_to_ethereum_amount(balance: Balance) -> U256 {
  assert_eq!(balance.coin.network(), NetworkId::Ethereum);
  assert_eq!(balance.coin.decimals(), 8);
  // Restore 10 decimals so we go from 8 decimals to 18 decimals
  // TODO: Document the expectation all integrated coins have 18 decimals
  let factor = U256::from(10_000_000_000u64);
  U256::from(balance.amount.0) * factor
}

#[derive(Clone)]
pub(crate) struct SmartContract {
  pub(crate) chain_id: U256,
}
impl smart_contract_scheduler::SmartContract<Rpc> for SmartContract {
  type SignableTransaction = SignableTransaction;

  fn rotate(
    &self,
    nonce: u64,
    retiring_key: KeyFor<Rpc>,
    new_key: KeyFor<Rpc>,
  ) -> (Self::SignableTransaction, EventualityFor<Rpc>) {
    let command = RouterCommand::UpdateSeraiKey {
      chain_id: self.chain_id,
      nonce: U256::try_from(nonce).unwrap(),
      key: PublicKey::new(new_key).expect("rotating to an invald key"),
    };
    (
      SignableTransaction(command.clone()),
      Eventuality(PublicKey::new(retiring_key).expect("retiring an invalid key"), command),
    )
  }
  fn fulfill(
    &self,
    nonce: u64,
    key: KeyFor<Rpc>,
    payments: Vec<Payment<AddressFor<Rpc>>>,
  ) -> Vec<(Self::SignableTransaction, EventualityFor<Rpc>)> {
    let mut outs = Vec::with_capacity(payments.len());
    for payment in payments {
      outs.push(OutInstruction {
        target: if let Some(data) = payment.data() {
          // This introspects the Call serialization format, expecting the first 20 bytes to
          // be the address
          // This avoids wasting the 20-bytes allocated within address
          let full_data = [<[u8; 20]>::from(*payment.address()).as_slice(), data].concat();
          let mut reader = full_data.as_slice();

          let mut calls = vec![];
          while !reader.is_empty() {
            let Ok(call) = Call::read(&mut reader) else { break };
            calls.push(call);
          }
          // The above must have executed at least once since reader contains the address
          assert_eq!(calls[0].to, <[u8; 20]>::from(*payment.address()));

          OutInstructionTarget::Calls(calls)
        } else {
          OutInstructionTarget::Direct((*payment.address()).into())
        },
        value: { balance_to_ethereum_amount(payment.balance()) },
      });
    }

    let command = RouterCommand::Execute {
      chain_id: self.chain_id,
      nonce: U256::try_from(nonce).unwrap(),
      outs,
    };

    vec![(
      SignableTransaction(command.clone()),
      Eventuality(PublicKey::new(key).expect("fulfilling payments with an invalid key"), command),
    )]
  }
}

pub(crate) type Scheduler = smart_contract_scheduler::Scheduler<Rpc, SmartContract>;
