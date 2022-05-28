use async_trait::async_trait;
use thiserror::Error;

pub mod coins;

#[cfg(test)]
mod tests;

trait Output: Sized {
  type Id;

  fn id(&self) -> Self::Id;
  fn amount(&self) -> u64;

  fn serialize(&self) -> Vec<u8>;
  fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self>;
}

#[derive(Error, Debug)]
enum CoinError {
  #[error("failed to connect to coin daemon")]
  ConnectionError
}

#[async_trait]
trait Coin {
  type Output: Output;
  type Address;

  async fn confirmations() -> usize;
  async fn max_inputs() -> usize;
  async fn max_outputs() -> usize;

  async fn get_height(&self) -> Result<usize, CoinError>;
  async fn get_outputs_in_block(&self, height: usize) -> Result<Vec<Self::Output>, CoinError>;
  async fn send(
    &self,
    payments: &[(Self::Address, u64)]
  ) -> Result<Vec<<Self::Output as Output>::Id>, CoinError>;
}
