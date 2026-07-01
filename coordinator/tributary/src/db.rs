use core::time::Duration;
use std::collections::HashMap;

use borsh::{BorshSerialize, BorshDeserialize};

use dkg::Participant;
use serai_coordinator_substrate::TributaryValidatorSetInfo;
use serai_primitives::{BlockHash, validator_sets::ExternalValidatorSet};

use messages::sign::{VariantSignId, SignId};

use serai_db::*;
use serai_cosign_types::CosignIntent;

use crate::transaction::SigningProtocolRound;

/// A topic within the database which the group participates in
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Topic {
  /// Vote to remove a participant
  RemoveParticipant {
    /// The participant to remove. Stored as the tributary index of participation
    participant: Participant,
  },

  // DkgParticipation isn't represented here as participations are immediately sent to the
  // processor, not accumulated within this database
  /// Participation in the signing protocol to confirm the DKG results on Substrate
  DkgConfirmation {
    /// The attempt number this is for
    attempt: u64,
    /// The round of the signing protocol
    round: SigningProtocolRound,
  },

  /// The local view of the SlashReport, to be aggregated into the final SlashReport
  SlashReport,

  /// Participation in a signing protocol
  Sign {
    /// The ID of the signing protocol
    id: VariantSignId,
    /// The attempt number this is for
    attempt: u64,
    /// The round of the signing protocol
    round: SigningProtocolRound,
  },
}

#[derive(Debug, PartialEq)]
pub(crate) enum Participating {
  Participated,
  Everyone,
}

impl Topic {
  // The topic used by the next attempt of this protocol
  pub(crate) fn next_attempt_topic(self) -> Option<Topic> {
    #[expect(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { attempt, round: _ } => Some(Topic::DkgConfirmation {
        attempt: attempt.checked_add(1)?,
        round: SigningProtocolRound::Preprocess,
      }),
      Topic::SlashReport => None,
      Topic::Sign { id, attempt, round: _ } => Some(Topic::Sign {
        id,
        attempt: attempt.checked_add(1)?,
        round: SigningProtocolRound::Preprocess,
      }),
    }
  }

  // The topic for the re-attempt to schedule
  pub(crate) fn reattempt_topic(self) -> Option<(u64, Topic)> {
    #[expect(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { attempt, round } => match round {
        SigningProtocolRound::Preprocess => {
          let next_attempt = attempt.checked_add(1)?;
          Some((
            next_attempt,
            Topic::DkgConfirmation {
              attempt: next_attempt,
              round: SigningProtocolRound::Preprocess,
            },
          ))
        }
        SigningProtocolRound::Share => None,
      },
      Topic::SlashReport => None,
      Topic::Sign { id, attempt, round } => match round {
        SigningProtocolRound::Preprocess => {
          let next_attempt = attempt.checked_add(1)?;
          Some((
            next_attempt,
            Topic::Sign { id, attempt: next_attempt, round: SigningProtocolRound::Preprocess },
          ))
        }
        SigningProtocolRound::Share => None,
      },
    }
  }

  /// The SignId for this topic
  ///
  /// Returns None if Topic isn't Topic::Sign
  pub(crate) fn sign_id(self, set: ExternalValidatorSet) -> Option<messages::sign::SignId> {
    #[expect(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { .. } => None,
      Topic::SlashReport => None,
      Topic::Sign { id, attempt, round: _ } => Some(SignId { session: set.session, id, attempt }),
    }
  }

  /// The SignId for this DKG Confirmation.
  ///
  /// This is undefined except for being consistent to the DKG Confirmation signing protocol and
  /// unique across sets.
  ///
  /// Returns None if Topic isn't Topic::DkgConfirmation.
  pub(crate) fn dkg_confirmation_sign_id(
    self,
    set: ExternalValidatorSet,
  ) -> Option<messages::sign::SignId> {
    #[expect(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { attempt, round: _ } => Some({
        let id = {
          let mut id = [0; 32];
          let encoded_set = borsh::to_vec(&set).unwrap();
          id[.. encoded_set.len()].copy_from_slice(&encoded_set);
          VariantSignId::Batch(id)
        };
        SignId { session: set.session, id, attempt }
      }),
      Topic::SlashReport => None,
      Topic::Sign { .. } => None,
    }
  }

  /// The topic which precedes this topic as a prerequisite
  ///
  /// The preceding topic must define this topic as succeeding
  pub(crate) fn preceding_topic(self) -> Option<Topic> {
    #[expect(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { attempt, round } => match round {
        SigningProtocolRound::Preprocess => None,
        SigningProtocolRound::Share => {
          Some(Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Preprocess })
        }
      },
      Topic::SlashReport => None,
      Topic::Sign { id, attempt, round } => match round {
        SigningProtocolRound::Preprocess => None,
        SigningProtocolRound::Share => {
          Some(Topic::Sign { id, attempt, round: SigningProtocolRound::Preprocess })
        }
      },
    }
  }

  /// The topic which succeeds this topic, with this topic as a prerequisite
  ///
  /// The succeeding topic must define this topic as preceding
  pub(crate) fn succeeding_topic(self) -> Option<Topic> {
    #[expect(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { attempt, round } => match round {
        SigningProtocolRound::Preprocess => {
          Some(Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Share })
        }
        SigningProtocolRound::Share => None,
      },
      Topic::SlashReport => None,
      Topic::Sign { id, attempt, round } => match round {
        SigningProtocolRound::Preprocess => {
          Some(Topic::Sign { id, attempt, round: SigningProtocolRound::Share })
        }
        SigningProtocolRound::Share => None,
      },
    }
  }

  /// If this topic requires recognition before entries are permitted for it.
  pub fn requires_recognition(&self) -> bool {
    #[expect(clippy::match_same_arms)]
    match self {
      // We don't require recognition to remove a participant
      Topic::RemoveParticipant { .. } => false,
      // We don't require recognition for the first attempt, solely the re-attempts
      Topic::DkgConfirmation { attempt, .. } => *attempt != 0,
      // We don't require recognition for the slash report
      Topic::SlashReport => false,
      // We do require recognition for every sign protocol
      Topic::Sign { .. } => true,
    }
  }

  pub(crate) fn participating(&self) -> Participating {
    #[expect(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => Participating::Everyone,
      Topic::DkgConfirmation { .. } => Participating::Participated,
      Topic::SlashReport => Participating::Everyone,
      Topic::Sign { .. } => Participating::Participated,
    }
  }
}

pub(crate) trait Borshy: BorshSerialize + BorshDeserialize {}
impl<T: BorshSerialize + BorshDeserialize> Borshy for T {}

/// The resulting data set from an accumulation
pub(crate) enum DataSet<D: Borshy> {
  /// Accumulating this did not produce a data set to act on
  /// (non-existent, not ready, prior handled, not participating, etc.)
  None,
  /// The data set was ready and we are participating in this event
  Participating(HashMap<Participant, D>),
}

create_db!(
  CoordinatorTributary {
    // The last handled tributary block's (number, hash).
    LastHandledTributaryBlock: (set: ExternalValidatorSet) -> (u64, [u8; 32]),

    // The slash points a participant has accrued, with u32::MAX representing a fatal slash.
    ParticipantTributarySlashPoints: (set: ExternalValidatorSet, participant: Participant) -> u32,

    // The cosign intent per Substrate block hashes.
    SubstrateCosignIntents:
      (set: ExternalValidatorSet, substrate_block_hash: BlockHash) -> CosignIntent,
    // The latest Substrate block to cosign.
    LatestSubstrateBlockToCosign: (set: ExternalValidatorSet) -> BlockHash,
    // The hash of the block we're actively cosigning.
    ActivelyCosigningHash: (set: ExternalValidatorSet) -> BlockHash,
    // If this block has already been cosigned.
    IsSubstrateCosigned: (set: ExternalValidatorSet, substrate_block_hash: BlockHash) -> (),

    // The plans to recognize upon a `Transaction::SubstrateBlock` being included on-chain.
    SubstrateBlockPlans: (
      set: ExternalValidatorSet,
      substrate_block_hash: BlockHash
    ) -> Vec<[u8; 32]>,

    // The weight accumulated for a topic.
    TopicsAccumulatedWeight: (set: ExternalValidatorSet, topic: Topic) -> u16,
    // The entries accumulated for a topic, by validator.
    TopicsParticipantAccumulatedEntries: <D: Borshy>(
      set: ExternalValidatorSet,
      topic: Topic,
      participant: Participant
    ) -> D,

    // Topics to be recognized as of a certain block number due to the reattempt protocol.
    BlocksReattemptTopics: (set: ExternalValidatorSet, block_number: u64) -> Vec<Topic>,
  }
);

db_channel!(
  CoordinatorTributaryChannels {
    // Messages to send to the processor
    ProcessorMessages: (set: ExternalValidatorSet) -> messages::CoordinatorMessage,
    // Messages for the DKG confirmation
    DkgConfirmationMessages: (set: ExternalValidatorSet) -> messages::sign::CoordinatorMessage,
    // Topics which have been explicitly recognized
    RecognizedTopics: (set: ExternalValidatorSet) -> Topic,
  }
);

// 5 minutes
#[cfg(not(feature = "longer-reattempts"))]
#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
pub(crate) const BASE_REATTEMPT_DELAY: u32 = Duration::from_mins(5)
  .as_millis()
  .div_ceil(tributary_sdk::tendermint::TARGET_BLOCK_TIME.as_millis())
  as u32;

// 10 minutes, intended for latent environments like the GitHub CI
#[cfg(feature = "longer-reattempts")]
#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
pub(crate) const BASE_REATTEMPT_DELAY: u32 = Duration::from_mins(10)
  .as_millis()
  .div_ceil(tributary_sdk::tendermint::TARGET_BLOCK_TIME.as_millis())
  as u32;

pub(crate) struct TributaryDb;
impl TributaryDb {
  pub(crate) fn last_handled_tributary_block(
    getter: &impl Get,
    set: ExternalValidatorSet,
  ) -> Option<(u64, [u8; 32])> {
    LastHandledTributaryBlock::get(getter, set)
  }
  pub(crate) fn set_last_handled_tributary_block(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    block_number: u64,
    block_hash: [u8; 32],
  ) {
    LastHandledTributaryBlock::set(txn, set, &(block_number, block_hash));
  }

  pub(crate) fn latest_substrate_block_to_cosign(
    getter: &impl Get,
    set: ExternalValidatorSet,
  ) -> Option<BlockHash> {
    LatestSubstrateBlockToCosign::get(getter, set)
  }
  pub(crate) fn set_latest_substrate_block_to_cosign(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    substrate_block_hash: BlockHash,
  ) {
    LatestSubstrateBlockToCosign::set(txn, set, &substrate_block_hash);
  }
  pub(crate) fn get_actively_cosigning_hash(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
  ) -> Option<BlockHash> {
    ActivelyCosigningHash::get(txn, set)
  }
  pub(crate) fn is_actively_cosigning(txn: &mut impl DbTxn, set: ExternalValidatorSet) -> bool {
    Self::get_actively_cosigning_hash(txn, set).is_some()
  }
  pub(crate) fn start_cosigning(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    substrate_block_hash: BlockHash,
    substrate_block_number: u64,
  ) {
    assert!(
      !Self::is_actively_cosigning(txn, set),
      "starting cosigning while set is already cosigning"
    );
    ActivelyCosigningHash::set(txn, set, &substrate_block_hash);

    Self::recognize_topic(
      txn,
      set,
      Topic::Sign {
        id: VariantSignId::Cosign(substrate_block_number),
        attempt: 0,
        round: SigningProtocolRound::Preprocess,
      },
    );
  }
  pub(crate) fn finish_cosigning(txn: &mut impl DbTxn, set: ExternalValidatorSet) {
    ActivelyCosigningHash::take(txn, set)
      .expect("tried to finish cosigning but set wasn't actively cosigning");
  }
  pub(crate) fn mark_cosigned(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    substrate_block_hash: BlockHash,
  ) {
    IsSubstrateCosigned::set(txn, set, substrate_block_hash, &());
  }
  pub(crate) fn is_cosigned(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    substrate_block_hash: BlockHash,
  ) -> bool {
    IsSubstrateCosigned::get(txn, set, substrate_block_hash).is_some()
  }

  /// The next topic requiring recognition which has been recognized by this Tributary.
  pub fn try_recv_topic_requiring_recognition(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
  ) -> Option<Topic> {
    RecognizedTopics::try_recv(txn, set)
  }
  pub(crate) fn recognize_topic(txn: &mut impl DbTxn, set: ExternalValidatorSet, topic: Topic) {
    TopicsAccumulatedWeight::set(txn, set, topic, &0);
    RecognizedTopics::send(txn, set, &topic);
  }
  pub(crate) fn is_topic_recognized(
    getter: &impl Get,
    set: ExternalValidatorSet,
    topic: Topic,
  ) -> bool {
    TopicsAccumulatedWeight::get(getter, set, topic).is_some()
  }

  pub(crate) fn start_of_block(txn: &mut impl DbTxn, set: ExternalValidatorSet, block_number: u64) {
    for topic in BlocksReattemptTopics::take(txn, set, block_number).unwrap_or(vec![]) {
      /*
        TODO: Slash all people who preprocessed but didn't share, and add a delay to their
        participations in future protocols. When we call accumulate, if the participant has no
        delay, their accumulation occurs immediately. Else, the accumulation occurs after the
        specified delay.

        This means even if faulty validators are first to preprocess, they won't be selected for
        the signing set unless there's a lack of less faulty validators available.

        We need to decrease this delay upon successful partipations, and set it to the maximum upon
        `f + 1` validators voting to fatally slash the validator in question. This won't issue the
        fatal slash but should still be effective.
      */
      Self::recognize_topic(txn, set, topic);
      if let Some(id) = topic.sign_id(set) {
        Self::send_message(txn, set, messages::sign::CoordinatorMessage::Reattempt { id });
      } else if let Some(id) = topic.dkg_confirmation_sign_id(set) {
        DkgConfirmationMessages::send(
          txn,
          set,
          &messages::sign::CoordinatorMessage::Reattempt { id },
        );
      }
    }
  }

  pub(crate) fn fatal_slash(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    participant: Participant,
    #[cfg_attr(coverage, allow(unused_variables))] reason: &str,
  ) {
    serai_env::warn!("{participant:?} fatally slashed: {reason}");
    ParticipantTributarySlashPoints::set(txn, set, participant, &u32::MAX);
  }

  pub(crate) fn is_fatally_slashed(
    getter: &impl Get,
    set: ExternalValidatorSet,
    participant: Participant,
  ) -> bool {
    ParticipantTributarySlashPoints::get(getter, set, participant).unwrap_or(0) == u32::MAX
  }

  pub(crate) fn accumulate<D: Borshy>(
    txn: &mut impl DbTxn,
    tributary_validator_set_info: &TributaryValidatorSetInfo,
    block_number: u64,
    topic: Topic,
    participant: Participant,
    data: &D,
  ) -> DataSet<D> {
    let weight = tributary_validator_set_info
      .tributary_validator_set
      .get_tributary_validator_by_consensus_index(&participant)
      .unwrap()
      .weight;
    let set = tributary_validator_set_info.set;

    // This function will only be called once for a (topic, participant) tuple due to how we handle
    // nonces on transactions (deterministically to the topic)
    assert!(
      txn.get(TopicsParticipantAccumulatedEntries::<D>::key(set, topic, participant)).is_none(),
      "accumulate called twice for the same (topic, participant) tuple"
    );

    let accumulated_weight = TopicsAccumulatedWeight::get(txn, set, topic);
    if topic.requires_recognition() && accumulated_weight.is_none() {
      Self::fatal_slash(
        txn,
        set,
        participant,
        "participated in unrecognized topic which requires recognition",
      );
      return DataSet::None;
    }
    let mut accumulated_weight = accumulated_weight.unwrap_or(0);

    // Check if there's a preceding topic, this validator participated
    let preceding_topic = topic.preceding_topic();
    if let Some(preceding_topic) = preceding_topic {
      // Use a raw key-existence check instead of `Accumulated::<D>::get` because the preceding
      // topic may have stored a different type (e.g. preprocess is [u8; 64], share is [u8; 32])
      if txn
        .get(TopicsParticipantAccumulatedEntries::<D>::key(set, preceding_topic, participant))
        .is_none()
      {
        Self::fatal_slash(
          txn,
          set,
          participant,
          "participated in topic without participating in prior",
        );
        return DataSet::None;
      }
    }

    let required_participation =
      tributary_validator_set_info.tributary_validator_set.required_participation();

    // The complete lack of validation on the data by these NOPs opens the potential for spam here

    // If we've already accumulated past the threshold, NOP
    if accumulated_weight >= required_participation {
      return DataSet::None;
    }
    // If this is for an old attempt, NOP
    if let Some(next_attempt_topic) = topic.next_attempt_topic() {
      if TopicsAccumulatedWeight::get(txn, set, next_attempt_topic).is_some() {
        return DataSet::None;
      }
    }

    // Accumulate the data
    accumulated_weight = accumulated_weight.checked_add(weight).unwrap_or_else(|| {
      panic!("accumulated {accumulated_weight} overflowed adding weight {weight}");
    });
    TopicsAccumulatedWeight::set(txn, set, topic, &accumulated_weight);
    TopicsParticipantAccumulatedEntries::<D>::set(txn, set, topic, participant, data);

    // Check if we now cross the weight threshold
    if accumulated_weight >= required_participation {
      // Queue this for re-attempt after enough time passes
      let reattempt_topic = topic.reattempt_topic();
      if let Some((attempt, reattempt_topic)) = reattempt_topic {
        // Linearly scale the time for the protocol with the attempt number
        let blocks_till_reattempt = attempt.min(10).saturating_mul(u64::from(BASE_REATTEMPT_DELAY));

        let recognize_at = block_number + blocks_till_reattempt;
        let mut queued =
          BlocksReattemptTopics::get(txn, set, recognize_at).unwrap_or(Vec::with_capacity(1));
        queued.push(reattempt_topic);
        BlocksReattemptTopics::set(txn, set, recognize_at, &queued);
      }

      // Register the succeeding topic
      let succeeding_topic = topic.succeeding_topic();
      if let Some(succeeding_topic) = succeeding_topic {
        Self::recognize_topic(txn, set, succeeding_topic);
      }

      let len_of_participants =
        tributary_validator_set_info.tributary_validator_set.consensus_tributary_validators.len();
      let mut data_set = HashMap::with_capacity(len_of_participants);
      for i in 1 ..= len_of_participants + 1 {
        let i_participant = Participant::new(u16::try_from(i).unwrap()).unwrap();
        if let Some(data) = TopicsParticipantAccumulatedEntries::get(txn, set, topic, i_participant)
        {
          if reattempt_topic.is_none() {
            TopicsParticipantAccumulatedEntries::<D>::del(txn, set, topic, i_participant);
          }
          data_set.insert(i_participant, data);
        }
      }
      let participated = data_set.contains_key(&participant);
      match topic.participating() {
        Participating::Participated => {
          if participated {
            DataSet::Participating(data_set)
          } else {
            DataSet::None
          }
        }
        Participating::Everyone => DataSet::Participating(data_set),
      }
    } else {
      DataSet::None
    }
  }

  pub(crate) fn send_message(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    message: impl Into<messages::CoordinatorMessage>,
  ) {
    ProcessorMessages::send(txn, set, &message.into());
  }
}
