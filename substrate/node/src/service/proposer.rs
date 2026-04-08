use core::{marker::PhantomData, future::Future};
use futures_util::future::{self, Ready, Either};

use sp_runtime::{generic::DigestItem, traits::Block};
use sp_blockchain::Error;
use sp_consensus::{ProposeArgs, Proposal, Proposer, Environment};
use sp_timestamp::Timestamp;

use serai_abi::{primitives::address::SeraiAddress, SeraiPreExecutionDigest};

/// The block proposer for the Serai network.
///
/// This is used to insert the `PreRuntime` digest the Serai runtime expects.
pub(super) struct SeraiProposer<B: Block, Underlying: Proposer<B, Error = Error>> {
  proposer_identity: SeraiAddress,
  underlying: Underlying,
  _block: PhantomData<B>,
}
impl<B: Block, Underlying: Proposer<B, Error = Error>> Proposer<B>
  for SeraiProposer<B, Underlying>
{
  type Error = Underlying::Error;
  type Proposal = Either<Ready<Result<Proposal<B>, Error>>, Underlying::Proposal>;

  fn propose(self, mut args: ProposeArgs<B>) -> Self::Proposal {
    let timestamp = match args
      .inherent_data
      .get_data::<Timestamp>(&sp_timestamp::INHERENT_IDENTIFIER)
      .map_err(|e| Error::Application(e.into()))
      .and_then(|timestamp| {
        timestamp.ok_or(Error::Application("missing timestamp inherent".into()))
      }) {
      Ok(timestamp) => timestamp,
      Err(e) => return Either::Left(future::ready(Err(e))),
    };

    // Insert our expected digest
    args.inherent_digests.logs.push(DigestItem::PreRuntime(
      SeraiPreExecutionDigest::CONSENSUS_ID,
      borsh::to_vec(&SeraiPreExecutionDigest {
        proposer: self.proposer_identity,
        unix_time_in_millis: timestamp.as_millis(),
      })
      .unwrap(),
    ));

    // Passthrough to the underlying proposer's `propose` function
    Either::Right(self.underlying.propose(args))
  }
}

// This shim works around an overflow and/or cycle in evaluating the following bounds
trait IsReady: Future {
  fn into_inner(self) -> Self::Output;
}
impl<T> IsReady for Ready<T> {
  fn into_inner(self) -> Self::Output {
    Ready::into_inner(self)
  }
}

/// The environment for producing blocks for the Serai network.
///
/// This wraps the underlying environment's proposer with our own `SeraiProposer` which will insert
/// the `PreRuntime` digest the Serai runtime expects.
pub(super) struct SeraiProposerFactory<
  B: Block,
  Underlying: Environment<B, Proposer: Proposer<B, Error = Error>>,
> {
  pub(super) proposer_identity: SeraiAddress,
  pub(super) underlying: Underlying,
  pub(super) _block: PhantomData<B>,
}
impl<B: Block, Underlying: Environment<B, Proposer: Proposer<B, Error = Error>>> Environment<B>
  for SeraiProposerFactory<B, Underlying>
where
  Underlying::Error: Send,
  Underlying::CreateProposer: IsReady,
{
  type CreateProposer = Ready<Result<Self::Proposer, Self::Error>>;
  type Proposer = SeraiProposer<B, Underlying::Proposer>;
  type Error = Underlying::Error;

  fn init(&mut self, parent_header: &B::Header) -> Self::CreateProposer {
    future::ready(self.underlying.init(parent_header).into_inner().map(|underlying| {
      SeraiProposer { proposer_identity: self.proposer_identity, underlying, _block: PhantomData }
    }))
  }
}
