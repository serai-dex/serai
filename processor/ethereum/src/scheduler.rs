use alloy_core::primitives::U256;

use serai_client::primitives::{NetworkId, Coin, Balance};

use serai_db::Db;

use primitives::Payment;
use scanner::{KeyFor, AddressFor, EventualityFor};

use ethereum_schnorr::PublicKey;
use ethereum_router::Coin as EthereumCoin;

use crate::{DAI, transaction::Action, rpc::Rpc};

fn coin_to_ethereum_coin(coin: Coin) -> EthereumCoin {
  assert_eq!(coin.network(), NetworkId::Ethereum);
  match coin {
    Coin::Ether => EthereumCoin::Ether,
    Coin::Dai => EthereumCoin::Erc20(DAI),
    _ => unreachable!(),
  }
}

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
impl<D: Db> smart_contract_scheduler::SmartContract<Rpc<D>> for SmartContract {
  type SignableTransaction = Action;

  fn rotate(
    &self,
    nonce: u64,
    _retiring_key: KeyFor<Rpc<D>>,
    new_key: KeyFor<Rpc<D>>,
  ) -> (Self::SignableTransaction, EventualityFor<Rpc<D>>) {
    let action = Action::SetKey {
      chain_id: self.chain_id,
      nonce,
      key: PublicKey::new(new_key).expect("rotating to an invald key"),
    };
    (action.clone(), action.eventuality())
  }

  fn fulfill(
    &self,
    nonce: u64,
    _key: KeyFor<Rpc<D>>,
    payments: Vec<Payment<AddressFor<Rpc<D>>>>,
  ) -> Vec<(Self::SignableTransaction, EventualityFor<Rpc<D>>)> {
    let mut outs = Vec::with_capacity(payments.len());
    for payment in payments {
      outs.push((
        payment.address().clone(),
        (
          coin_to_ethereum_coin(payment.balance().coin),
          balance_to_ethereum_amount(payment.balance()),
        ),
      ));
    }

    // TODO: Per-batch gas limit
    // TODO: Create several batches
    // TODO: Handle fees
    let action = Action::Batch { chain_id: self.chain_id, nonce, outs };

    vec![(action.clone(), action.eventuality())]
  }
}

pub(crate) type Scheduler<D> = smart_contract_scheduler::Scheduler<Rpc<D>, SmartContract>;
