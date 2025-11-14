use std::time::Duration;

use sp_runtime::Digest;
use sp_consensus::{InherentData, DisableProofRecording};

use serai_abi::{SeraiPreExecutionDigest, SubstrateHeader as Header, SubstrateBlock as Block};

use super::{FullClient, TransactionPool};

type UnderlyingProposer =
  sc_basic_authorship::Proposer<Block, FullClient, TransactionPool, DisableProofRecording>;
pub struct Proposer(UnderlyingProposer);
impl sp_consensus::Proposer<Block> for Proposer {
  type Error = <UnderlyingProposer as sp_consensus::Proposer<Block>>::Error;
  type Proposal = <UnderlyingProposer as sp_consensus::Proposer<Block>>::Proposal;
  type ProofRecording = DisableProofRecording;
  type Proof = ();

  fn propose(
    self,
    inherent_data: InherentData,
    mut inherent_digests: Digest,
    max_duration: Duration,
    block_size_limit: Option<usize>,
  ) -> Self::Proposal {
    Box::pin(async move {
      // Insert our expected digest
      inherent_digests.logs.push(sp_runtime::generic::DigestItem::PreRuntime(
        SeraiPreExecutionDigest::CONSENSUS_ID,
        borsh::to_vec(&SeraiPreExecutionDigest {
          unix_time_in_millis: inherent_data
            .get_data::<sp_timestamp::Timestamp>(&sp_timestamp::INHERENT_IDENTIFIER)
            .map_err(|err| sp_blockchain::Error::Application(err.into()))?
            .ok_or(sp_blockchain::Error::Application("missing timestamp inherent".into()))?
            .as_millis(),
        })
        .unwrap(),
      ));

      // Call the underlying propose function
      self.0.propose(inherent_data, inherent_digests, max_duration, block_size_limit).await
    })
  }
}

type UnderlyingFactory =
  sc_basic_authorship::ProposerFactory<TransactionPool, FullClient, DisableProofRecording>;
pub struct ProposerFactory(pub UnderlyingFactory);
impl sp_consensus::Environment<Block> for ProposerFactory {
  type CreateProposer = core::future::Ready<Result<Proposer, Self::Error>>;
  type Proposer = Proposer;
  type Error = <UnderlyingFactory as sp_consensus::Environment<Block>>::Error;
  fn init(&mut self, parent_header: &Header) -> Self::CreateProposer {
    core::future::ready(self.0.init(parent_header).into_inner().map(Proposer))
  }
}
