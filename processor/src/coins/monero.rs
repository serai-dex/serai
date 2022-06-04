use std::sync::Arc;

use async_trait::async_trait;
use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::{scalar::Scalar, edwards::CompressedEdwardsY};

use dalek_ff_group as dfg;
use frost::MultisigKeys;

use monero::util::address::Address;
use monero_serai::{
  frost::Ed25519,
  transaction::{Timelock, Transaction},
  rpc::Rpc,
  wallet::{SpendableOutput, SignableTransaction}
};

use crate::{Output as OutputTrait, CoinError, Coin, view_key};

#[derive(Clone)]
pub struct Output(SpendableOutput);
impl OutputTrait for Output {
  // While we could use (tx, o), using the key ensures we won't be susceptible to the burning bug.
  // While the Monero library offers a variant which allows senders to ensure their TXs have unique
  // output keys, Serai can still be targeted using the classic burning bug
  type Id = CompressedEdwardsY;

  fn id(&self) -> Self::Id {
    self.0.key.compress()
  }

  fn amount(&self) -> u64 {
    self.0.commitment.amount
  }

  fn serialize(&self) -> Vec<u8> {
    self.0.serialize()
  }

  fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
    SpendableOutput::deserialize(reader).map(|o| Output(o))
  }
}

impl From<SpendableOutput> for Output {
  fn from(output: SpendableOutput) -> Output {
    Output(output)
  }
}

pub struct Monero {
  rpc: Rpc,
  view: Scalar
}

impl Monero {
  pub fn new(url: String) -> Monero {
    Monero {
      rpc: Rpc::new(url),
      view: *view_key::<Monero>(0)
    }
  }
}

#[async_trait]
impl Coin for Monero {
  type Curve = Ed25519;

  type Output = Output;
  type Block = Vec<Transaction>;
  type SignableTransaction = SignableTransaction;

  type Address = Address;

  const ID: &'static [u8] = b"Monero";
  const CONFIRMATIONS: usize = 10;
  // Testnet TX bb4d188a4c571f2f0de70dca9d475abc19078c10ffa8def26dd4f63ce1bcfd79 uses 146 inputs
  // while using less than 100kb of space, albeit with just 2 outputs (though outputs share a BP)
  // The TX size limit is half the contextual median block weight, where said weight is >= 300,000
  // This means any TX which fits into 150kb will be accepted by Monero
  // 128, even with 16 outputs, should fit into 100kb. Further efficiency by 192 may be viable
  // TODO: Get hard numbers and tune
  const MAX_INPUTS: usize = 128;
  const MAX_OUTPUTS: usize = 16;

  async fn get_height(&self) -> Result<usize, CoinError> {
    self.rpc.get_height().await.map_err(|_| CoinError::ConnectionError)
  }

  async fn get_block(&self, height: usize) -> Result<Self::Block, CoinError> {
    self.rpc.get_block_transactions_possible(height).await.map_err(|_| CoinError::ConnectionError)
  }

  async fn get_outputs(&self, block: &Self::Block, key: dfg::EdwardsPoint) -> Vec<Self::Output> {
    block
      .iter()
      .flat_map(|tx| {
        let (outputs, timelock) = tx.scan(self.view, key.0);
        if timelock == Timelock::None {
          outputs
        } else {
          vec![]
        }
      })
      .map(Output::from)
      .collect()
  }

  async fn prepare_send(
    &self,
    _keys: Arc<MultisigKeys<Ed25519>>,
    _label: Vec<u8>,
    _height: usize,
    _inputs: Vec<Output>,
    _payments: &[(Address, u64)]
  ) -> Result<SignableTransaction, CoinError> {
    todo!()
  }

  async fn attempt_send<R: RngCore + CryptoRng + std::marker::Send>(
    &self,
    _rng: &mut R,
    _transaction: SignableTransaction,
    _included: &[u16]
  ) -> Result<(Vec<u8>, Vec<<Self::Output as OutputTrait>::Id>), CoinError> {
    todo!()
  }
}
