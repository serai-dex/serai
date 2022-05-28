use async_trait::async_trait;

use curve25519_dalek::{traits::Identity, scalar::Scalar, edwards::EdwardsPoint};

use monero::util::address::Address;
use monero_serai::{/*transaction::Output, */ rpc::Rpc, wallet::SpendableOutput};

use crate::{Output as OutputTrait, CoinError, Coin};

pub struct Output(SpendableOutput);
impl OutputTrait for Output {
  // If Monero ever does support more than 255 outputs at once, which it could, this u8 could be a
  // u16 which serializes as little endian, dropping the last byte if empty, without conflict
  type Id = ([u8; 32], u8);

  fn id(&self) -> Self::Id {
    (self.0.tx, self.0.o.try_into().unwrap())
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
  view: Scalar,
  spend: EdwardsPoint
}

impl Monero {
  pub fn new(url: String) -> Monero {
    Monero {
      rpc: Rpc::new(url),
      view: Scalar::zero(),
      spend: EdwardsPoint::identity()
    }
  }
}

#[async_trait]
impl Coin for Monero {
  type Output = Output;
  type Address = Address;

  async fn confirmations() -> usize { 10 }
  async fn max_inputs() -> usize { 16 } // TODO
  async fn max_outputs() -> usize { 16 }

  async fn get_height(&self) -> Result<usize, CoinError> {
    self.rpc.get_height().await.map_err(|_| CoinError::ConnectionError)
  }

  async fn get_outputs_in_block(&self, height: usize) -> Result<Vec<Self::Output>, CoinError> {
    Ok(
      self.rpc.get_block_transactions_possible(height).await.map_err(|_| CoinError::ConnectionError)?
        .iter().flat_map(|tx| tx.scan(self.view, self.spend)).map(Output::from).collect()
    )
  }

  async fn send(
    &self,
    _payments: &[(Address, u64)]
  ) -> Result<Vec<<Self::Output as OutputTrait>::Id>, CoinError> {
    todo!()
  }
}
