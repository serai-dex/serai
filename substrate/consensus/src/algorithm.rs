use sp_core::U256;

use sc_consensus_pow::{Error, PowAlgorithm};
use sp_consensus_pow::Seal;

use sp_runtime::{generic::BlockId, traits::Block as BlockT};

#[derive(Clone)]
pub struct AcceptAny;
impl<B: BlockT> PowAlgorithm<B> for AcceptAny {
  type Difficulty = U256;

  fn difficulty(&self, _: B::Hash) -> Result<Self::Difficulty, Error<B>> {
    Ok(U256::one())
  }

  fn verify(
    &self,
    _: &BlockId<B>,
    _: &B::Hash,
    _: Option<&[u8]>,
    _: &Seal,
    _: Self::Difficulty,
  ) -> Result<bool, Error<B>> {
    Ok(true)
  }
}
