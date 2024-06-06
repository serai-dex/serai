use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use parity_scale_codec::Encode;
use serai_db::{Get, DbTxn, Db};

use crate::{
  time::CanonicalInstant,
  ext::{RoundNumber, BlockNumber, Block, Network},
  round::RoundData,
  message_log::MessageLog,
  Step, Data, DataFor, Message, MessageFor,
};

pub(crate) struct BlockData<N: Network> {
  db: N::Db,
  genesis: [u8; 32],

  pub(crate) number: BlockNumber,
  pub(crate) validator_id: Option<N::ValidatorId>,
  pub(crate) proposal: Option<N::Block>,

  pub(crate) log: MessageLog<N>,
  pub(crate) slashes: HashSet<N::ValidatorId>,
  // We track the end times of each round for two reasons:
  // 1) Knowing the start time of the next round
  // 2) Validating precommits, which include the end time of the round which produced it
  // This HashMap contains the end time of the round we're currently in and every round prior
  pub(crate) end_time: HashMap<RoundNumber, CanonicalInstant>,

  pub(crate) round: Option<RoundData<N>>,

  pub(crate) locked: Option<(RoundNumber, <N::Block as Block>::Id)>,
  pub(crate) valid: Option<(RoundNumber, N::Block)>,
}

impl<N: Network> BlockData<N> {
  pub(crate) fn new(
    db: N::Db,
    genesis: [u8; 32],
    weights: Arc<N::Weights>,
    number: BlockNumber,
    validator_id: Option<N::ValidatorId>,
    proposal: Option<N::Block>,
  ) -> BlockData<N> {
    BlockData {
      db,
      genesis,

      number,
      validator_id,
      proposal,

      log: MessageLog::new(weights),
      slashes: HashSet::new(),
      end_time: HashMap::new(),

      // The caller of BlockData::new is expected to be populated after by the caller
      round: None,

      locked: None,
      valid: None,
    }
  }

  pub(crate) fn round(&self) -> &RoundData<N> {
    self.round.as_ref().unwrap()
  }

  pub(crate) fn round_mut(&mut self) -> &mut RoundData<N> {
    self.round.as_mut().unwrap()
  }

  // Populate the end time up to the specified round
  // This is generally used when moving to the next round, where this will only populate one time,
  // yet is also used when jumping rounds (when 33% of the validators are on a round ahead of us)
  pub(crate) fn populate_end_time(&mut self, round: RoundNumber) {
    // Starts from the current round since we only start the current round once we have have all
    // the prior time data
    for r in (self.round().number.0 + 1) ..= round.0 {
      self.end_time.insert(
        RoundNumber(r),
        RoundData::<N>::new(RoundNumber(r), self.end_time[&RoundNumber(r - 1)]).end_time(),
      );
    }
  }

  // Start a new round. Optionally takes in the time for when this is the first round, and the time
  // isn't simply the time of the prior round (yet rather the prior block). Returns the proposal
  // data, if we are the proposer.
  pub(crate) fn new_round(
    &mut self,
    round: RoundNumber,
    proposer: N::ValidatorId,
    time: Option<CanonicalInstant>,
  ) -> Option<DataFor<N>> {
    debug_assert_eq!(round.0 == 0, time.is_some());

    // If this is the first round, we don't have a prior round's end time to use as the start
    // We use the passed in time instead
    // If this isn't the first round, ensure we have the prior round's end time by populating the
    // map with all rounds till this round
    // This can happen we jump from round x to round x+n, where n != 1
    // The paper says to do so whenever you observe a sufficient amount of peers on a higher round
    if round.0 != 0 {
      self.populate_end_time(round);
    }

    // 11-13
    self.round = Some(RoundData::<N>::new(
      round,
      time.unwrap_or_else(|| self.end_time[&RoundNumber(round.0 - 1)]),
    ));
    self.end_time.insert(round, self.round().end_time());

    // 14-21
    if Some(proposer) == self.validator_id {
      let (round, block) = self.valid.clone().unzip();
      block.or_else(|| self.proposal.clone()).map(|block| Data::Proposal(round, block))
    } else {
      self.round_mut().set_timeout(Step::Propose);
      None
    }
  }

  // Transform Data into an actual Message, using the contextual data from this block
  pub(crate) fn message(&mut self, data: DataFor<N>) -> Option<MessageFor<N>> {
    debug_assert_eq!(
      self.round().step,
      match data.step() {
        Step::Propose | Step::Prevote => Step::Propose,
        Step::Precommit => Step::Prevote,
      },
    );
    // Tendermint always sets the round's step to whatever it just broadcasted
    // Consolidate all of those here to ensure they aren't missed by an oversight
    // 27, 33, 41, 46, 60, 64
    self.round_mut().step = data.step();

    // Only return a message to if we're actually a current validator
    let round_number = self.round().number;
    let res = self.validator_id.map(|validator_id| Message {
      sender: validator_id,
      block: self.number,
      round: round_number,
      data,
    });

    if let Some(res) = res.as_ref() {
      const LATEST_BLOCK_KEY: &[u8] = b"tendermint-machine-sent_block";
      const LATEST_ROUND_KEY: &[u8] = b"tendermint-machine-sent_round";
      const PROPOSE_KEY: &[u8] = b"tendermint-machine-sent_propose";
      const PEVOTE_KEY: &[u8] = b"tendermint-machine-sent_prevote";
      const PRECOMMIT_KEY: &[u8] = b"tendermint-machine-sent_commit";

      let genesis = self.genesis;
      let key = |prefix: &[u8]| [prefix, &genesis].concat();

      let mut txn = self.db.txn();

      // Ensure we haven't prior sent a message for a future block/round
      let last_block_or_round = |txn: &mut <N::Db as Db>::Transaction<'_>, prefix, current| {
        let key = key(prefix);
        let latest =
          u64::from_le_bytes(txn.get(key.as_slice()).unwrap_or(vec![0; 8]).try_into().unwrap());
        if latest > current {
          None?;
        }
        if current > latest {
          txn.put(&key, current.to_le_bytes());
          return Some(true);
        }
        Some(false)
      };
      let new_block = last_block_or_round(&mut txn, LATEST_BLOCK_KEY, self.number.0)?;
      if new_block {
        // Delete the latest round key
        txn.del(key(LATEST_ROUND_KEY));
      }
      let new_round = last_block_or_round(&mut txn, LATEST_ROUND_KEY, round_number.0.into())?;
      if new_block || new_round {
        // Delete the messages for the old round
        txn.del(key(PROPOSE_KEY));
        txn.del(key(PEVOTE_KEY));
        txn.del(key(PRECOMMIT_KEY));
      }

      // Check we haven't sent this message within this round
      let msg_key = key(match res.data.step() {
        Step::Propose => PROPOSE_KEY,
        Step::Prevote => PEVOTE_KEY,
        Step::Precommit => PRECOMMIT_KEY,
      });
      if txn.get(&msg_key).is_some() {
        assert!(!new_block);
        assert!(!new_round);
        None?;
      }
      // Put this message to the DB
      txn.put(&msg_key, res.encode());

      txn.commit();
    }

    res
  }
}
