use crate::ScannerFeed;

/// An enum representing the stage of a multisig within its lifetime.
///
/// This corresponds to `spec/processor/Multisig Rotation.md`, which details steps 1-8 of the
/// rotation process. Steps 7-8 regard a multisig which isn't retiring yet retired, and
/// accordingly, no longer exists, so they are not modelled here (as this only models active
/// multisigs. Inactive multisigs aren't represented in the first place).
#[derive(Clone, Copy, PartialEq)]
pub enum LifetimeStage {
  /// A new multisig, once active, shouldn't actually start receiving coins until several blocks
  /// later. If any UI is premature in sending to this multisig, we delay to report the outputs to
  /// prevent some DoS concerns.
  ///
  /// This represents steps 1-3 for a new multisig.
  ActiveYetNotReporting,
  /// Active with all outputs being reported on-chain.
  ///
  /// This represents step 4 onwards for a new multisig.
  Active,
  /// Retiring with all outputs being reported on-chain.
  ///
  /// This represents step 4 for a retiring multisig.
  UsingNewForChange,
  /// Retiring with outputs being forwarded, reported on-chain once forwarded.
  ///
  /// This represents step 5 for a retiring multisig.
  Forwarding,
  /// Retiring with only existing obligations being handled.
  ///
  /// This represents step 6 for a retiring multisig.
  ///
  /// Steps 7 and 8 are represented by the retiring multisig no longer existing, and these states
  /// are only for multisigs which actively exist.
  Finishing,
}

/// The lifetime of the multisig, including various block numbers.
pub(crate) struct Lifetime {
  pub(crate) stage: LifetimeStage,
  pub(crate) block_at_which_reporting_starts: u64,
  // This is only Some if the next key's activation block number is passed to calculate, and the
  // stage is at least `LifetimeStage::Active.`
  pub(crate) block_at_which_forwarding_starts: Option<u64>,
}

impl Lifetime {
  /// Get the lifetime of this multisig.
  ///
  /// Panics if the multisig being calculated for isn't actually active and a variety of other
  /// insane cases.
  pub(crate) fn calculate<S: ScannerFeed>(
    block_number: u64,
    activation_block_number: u64,
    next_keys_activation_block_number: Option<u64>,
  ) -> Self {
    assert!(
      activation_block_number >= block_number,
      "calculating lifetime stage for an inactive multisig"
    );
    // This is exclusive, not inclusive, since we want a CONFIRMATIONS + 10 minutes window and the
    // activation block itself is the first block within this window
    let active_yet_not_reporting_end_block =
      activation_block_number + S::CONFIRMATIONS + S::TEN_MINUTES;
    // The exclusive end block is the inclusive start block
    let block_at_which_reporting_starts = active_yet_not_reporting_end_block;
    if block_number < active_yet_not_reporting_end_block {
      return Lifetime {
        stage: LifetimeStage::ActiveYetNotReporting,
        block_at_which_reporting_starts,
        block_at_which_forwarding_starts: None,
      };
    }

    let Some(next_keys_activation_block_number) = next_keys_activation_block_number else {
      // If there is no next multisig, this is the active multisig
      return Lifetime {
        stage: LifetimeStage::Active,
        block_at_which_reporting_starts,
        block_at_which_forwarding_starts: None,
      };
    };

    assert!(
      next_keys_activation_block_number > active_yet_not_reporting_end_block,
      "next set of keys activated before this multisig activated"
    );

    let new_active_yet_not_reporting_end_block =
      next_keys_activation_block_number + S::CONFIRMATIONS + S::TEN_MINUTES;
    let new_active_and_used_for_change_end_block =
      new_active_yet_not_reporting_end_block + S::CONFIRMATIONS;
    // The exclusive end block is the inclusive start block
    let block_at_which_forwarding_starts = Some(new_active_and_used_for_change_end_block);

    // If the new multisig is still having its activation block finalized on-chain, this multisig
    // is still active (step 3)
    if block_number < new_active_yet_not_reporting_end_block {
      return Lifetime {
        stage: LifetimeStage::Active,
        block_at_which_reporting_starts,
        block_at_which_forwarding_starts,
      };
    }

    // Step 4 details a further CONFIRMATIONS
    if block_number < new_active_and_used_for_change_end_block {
      return Lifetime {
        stage: LifetimeStage::UsingNewForChange,
        block_at_which_reporting_starts,
        block_at_which_forwarding_starts,
      };
    }

    // Step 5 details a further 6 hours
    // 6 hours = 6 * 60 minutes = 6 * 6 * 10 minutes
    let new_active_and_forwarded_to_end_block =
      new_active_and_used_for_change_end_block + (6 * 6 * S::TEN_MINUTES);
    if block_number < new_active_and_forwarded_to_end_block {
      return Lifetime {
        stage: LifetimeStage::Forwarding,
        block_at_which_reporting_starts,
        block_at_which_forwarding_starts,
      };
    }

    // Step 6
    Lifetime {
      stage: LifetimeStage::Finishing,
      block_at_which_reporting_starts,
      block_at_which_forwarding_starts,
    }
  }
}
