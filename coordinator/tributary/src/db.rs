use std::collections::HashMap;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{BlockHash, validator_sets::ExternalValidatorSet, address::SeraiAddress};

use messages::sign::{VariantSignId, SignId};

use serai_db::*;

use serai_cosign_types::CosignIntent;

use crate::transaction::SigningProtocolRound;

/// A topic within the database which the group participates in
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Topic {
  /// Vote to remove a participant
  RemoveParticipant {
    /// The participant to remove
    participant: SeraiAddress,
  },

  // DkgParticipation isn't represented here as participations are immediately sent to the
  // processor, not accumulated within this database
  /// Participation in the signing protocol to confirm the DKG results on Substrate
  DkgConfirmation {
    /// The attempt number this is for
    attempt: u32,
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
    attempt: u32,
    /// The round of the signing protocol
    round: SigningProtocolRound,
  },
}

#[derive(Debug, PartialEq)]
pub(crate) enum Participating {
  Participated,
  Everyone,
}

pub(crate) fn required_participation(n: u16) -> u16 {
  // All of our topics require 2/3rds participation
  n.checked_mul(2).unwrap_or_else(|| panic!("required_participation overflowed: {n} * 2")) / 3 + 1
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
  pub(crate) fn reattempt_topic(self) -> Option<(u32, Topic)> {
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
  Participating(HashMap<SeraiAddress, D>),
}

create_db!(
  CoordinatorTributary {
    // The last handled tributary block's (number, hash)
    LastHandledTributaryBlock: (set: ExternalValidatorSet) -> (u64, [u8; 32]),

    // The slash points a validator has accrued, with u32::MAX representing a fatal slash.
    SlashPoints: (set: ExternalValidatorSet, validator: SeraiAddress) -> u32,

    // The cosign intent for a Substrate block
    CosignIntents: (set: ExternalValidatorSet, substrate_block_hash: BlockHash) -> CosignIntent,
    // The latest Substrate block to cosign.
    LatestSubstrateBlockToCosign: (set: ExternalValidatorSet) -> BlockHash,
    // The hash of the block we're actively cosigning.
    ActivelyCosigning: (set: ExternalValidatorSet) -> BlockHash,
    // If this block has already been cosigned.
    Cosigned: (set: ExternalValidatorSet, substrate_block_hash: BlockHash) -> (),

    // The plans to recognize upon a `Transaction::SubstrateBlock` being included on-chain.
    SubstrateBlockPlans: (
      set: ExternalValidatorSet,
      substrate_block_hash: BlockHash
    ) -> Vec<[u8; 32]>,

    // The weight accumulated for a topic.
    AccumulatedWeight: (set: ExternalValidatorSet, topic: Topic) -> u16,
    // The entries accumulated for a topic, by validator.
    Accumulated: <D: Borshy>(
      set: ExternalValidatorSet,
      topic: Topic,
      validator: SeraiAddress
    ) -> D,

    // Topics to be recognized as of a certain block number due to the reattempt protocol.
    Reattempt: (set: ExternalValidatorSet, block_number: u64) -> Vec<Topic>,
  }
);

db_channel!(
  CoordinatorTributary {
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
pub(crate) const BASE_REATTEMPT_DELAY: u32 =
  (5u32 * 60 * 1000).div_ceil(tributary_sdk::tendermint::TARGET_BLOCK_TIME);

// 10 minutes, intended for latent environments like the GitHub CI
#[cfg(feature = "longer-reattempts")]
pub(crate) const BASE_REATTEMPT_DELAY: u32 =
  (10u32 * 60 * 1000).div_ceil(tributary_sdk::tendermint::TARGET_BLOCK_TIME);

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
  pub(crate) fn actively_cosigning(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
  ) -> Option<BlockHash> {
    ActivelyCosigning::get(txn, set)
  }
  pub(crate) fn start_cosigning(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    substrate_block_hash: BlockHash,
    substrate_block_number: u64,
  ) {
    assert!(
      ActivelyCosigning::get(txn, set).is_none(),
      "starting cosigning while already cosigning"
    );
    ActivelyCosigning::set(txn, set, &substrate_block_hash);

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
    ActivelyCosigning::take(txn, set)
      .expect("tried to finish cosigning but wasn't actively cosigning");
  }
  pub(crate) fn mark_cosigned(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    substrate_block_hash: BlockHash,
  ) {
    Cosigned::set(txn, set, substrate_block_hash, &());
  }
  pub(crate) fn cosigned(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    substrate_block_hash: BlockHash,
  ) -> bool {
    Cosigned::get(txn, set, substrate_block_hash).is_some()
  }

  /// The next topic requiring recognition which has been recognized by this Tributary.
  pub fn try_recv_topic_requiring_recognition(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
  ) -> Option<Topic> {
    RecognizedTopics::try_recv(txn, set)
  }
  pub(crate) fn recognize_topic(txn: &mut impl DbTxn, set: ExternalValidatorSet, topic: Topic) {
    AccumulatedWeight::set(txn, set, topic, &0);
    RecognizedTopics::send(txn, set, &topic);
  }
  pub(crate) fn recognized(getter: &impl Get, set: ExternalValidatorSet, topic: Topic) -> bool {
    AccumulatedWeight::get(getter, set, topic).is_some()
  }

  pub(crate) fn start_of_block(txn: &mut impl DbTxn, set: ExternalValidatorSet, block_number: u64) {
    for topic in Reattempt::take(txn, set, block_number).unwrap_or(vec![]) {
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
    validator: SeraiAddress,
    #[cfg_attr(coverage, allow(unused_variables))] reason: &str,
  ) {
    serai_env::warn!("{validator} fatally slashed: {reason}");
    SlashPoints::set(txn, set, validator, &u32::MAX);
  }

  pub(crate) fn is_fatally_slashed(
    getter: &impl Get,
    set: ExternalValidatorSet,
    validator: SeraiAddress,
  ) -> bool {
    SlashPoints::get(getter, set, validator).unwrap_or(0) == u32::MAX
  }

  #[expect(clippy::too_many_arguments)]
  pub(crate) fn accumulate<D: Borshy>(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
    validators: &[SeraiAddress],
    total_weight: u16,
    block_number: u64,
    topic: Topic,
    validator: SeraiAddress,
    validator_weight: u16,
    data: &D,
  ) -> DataSet<D> {
    // This function will only be called once for a (validator, topic) tuple due to how we handle
    // nonces on transactions (deterministically to the topic)
    assert!(
      txn.get(Accumulated::<D>::key(set, topic, validator)).is_none(),
      "accumulate called twice for the same (validator, topic) tuple: \
       the nonce system should have prevented this"
    );

    let accumulated_weight = AccumulatedWeight::get(txn, set, topic);
    if topic.requires_recognition() && accumulated_weight.is_none() {
      Self::fatal_slash(
        txn,
        set,
        validator,
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
      if txn.get(Accumulated::<D>::key(set, preceding_topic, validator)).is_none() {
        Self::fatal_slash(
          txn,
          set,
          validator,
          "participated in topic without participating in prior",
        );
        return DataSet::None;
      }
    }

    let required_participation = required_participation(total_weight);

    // The complete lack of validation on the data by these NOPs opens the potential for spam here

    // If we've already accumulated past the threshold, NOP
    if accumulated_weight >= required_participation {
      return DataSet::None;
    }
    // If this is for an old attempt, NOP
    if let Some(next_attempt_topic) = topic.next_attempt_topic() {
      if AccumulatedWeight::get(txn, set, next_attempt_topic).is_some() {
        return DataSet::None;
      }
    }

    // Accumulate the data
    accumulated_weight = accumulated_weight.checked_add(validator_weight).unwrap_or_else(|| {
      panic!(
        "accumulated_weight {accumulated_weight} overflowed adding validator_weight {validator_weight}",
      )
    });
    AccumulatedWeight::set(txn, set, topic, &accumulated_weight);
    Accumulated::set(txn, set, topic, validator, data);

    // Check if we now cross the weight threshold
    if accumulated_weight >= required_participation {
      // Queue this for re-attempt after enough time passes
      let reattempt_topic = topic.reattempt_topic();
      if let Some((attempt, reattempt_topic)) = reattempt_topic {
        // Linearly scale the time for the protocol with the attempt number
        let blocks_till_reattempt = u64::from(attempt) * u64::from(BASE_REATTEMPT_DELAY);

        #[expect(clippy::expect_fun_call)]
        let recognize_at = block_number.checked_add(blocks_till_reattempt).unwrap_or_else(|| {
          panic!(
            "recognize_at overflowed: block_number {block_number} + delay {blocks_till_reattempt}",
          );
        });
        let mut queued = Reattempt::get(txn, set, recognize_at).unwrap_or(Vec::with_capacity(1));
        queued.push(reattempt_topic);
        Reattempt::set(txn, set, recognize_at, &queued);
      }

      // Register the succeeding topic
      let succeeding_topic = topic.succeeding_topic();
      if let Some(succeeding_topic) = succeeding_topic {
        Self::recognize_topic(txn, set, succeeding_topic);
      }

      // Fetch and return all participations
      let mut data_set = HashMap::with_capacity(validators.len());
      for validator in validators {
        if let Some(data) = Accumulated::<D>::get(txn, set, topic, *validator) {
          // Clean this data up if there's not a re-attempt topic
          // If there is a re-attempt topic, we clean it up upon re-attempt
          if reattempt_topic.is_none() {
            Accumulated::<D>::del(txn, set, topic, *validator);
          }
          data_set.insert(*validator, data);
        }
      }
      let participated = data_set.contains_key(&validator);
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
