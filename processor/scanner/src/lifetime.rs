use crate::ScannerFeed;

/// An enum representing the stage of a multisig within its lifetime.
///
/// This corresponds to `spec/processor/Multisig Rotation.md`, which details steps 1-8 of the
/// rotation process. Steps 7-8 regard a multisig which isn't retiring yet retired, and
/// accordingly, no longer exists, so they are not modelled here (as this only models active
/// multisigs. Inactive multisigs aren't represented in the first place).
#[derive(PartialEq)]
pub(crate) enum LifetimeStage {
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

impl LifetimeStage {
  /// Get the stage of its lifetime this multisig is in, and the block at which we start reporting
  /// outputs to it.
  ///
  /// Panics if the multisig being calculated for isn't actually active and a variety of other
  /// insane cases.
  pub(crate) fn calculate_stage_and_reporting_start_block<S: ScannerFeed>(
    block_number: u64,
    activation_block_number: u64,
    next_keys_activation_block_number: Option<u64>,
  ) -> (Self, u64) {
    assert!(
      activation_block_number >= block_number,
      "calculating lifetime stage for an inactive multisig"
    );
    // This is exclusive, not inclusive, since we want a CONFIRMATIONS + 10 minutes window and the
    // activation block itself is the first block within this window
    let active_yet_not_reporting_end_block =
      activation_block_number + S::CONFIRMATIONS + S::TEN_MINUTES;
    // The exclusive end block is the inclusive start block
    let reporting_start_block = active_yet_not_reporting_end_block;
    if block_number < active_yet_not_reporting_end_block {
      return (LifetimeStage::ActiveYetNotReporting, reporting_start_block);
    }

    let Some(next_keys_activation_block_number) = next_keys_activation_block_number else {
      // If there is no next multisig, this is the active multisig
      return (LifetimeStage::Active, reporting_start_block);
    };

    assert!(
      next_keys_activation_block_number > active_yet_not_reporting_end_block,
      "next set of keys activated before this multisig activated"
    );

    // If the new multisig is still having its activation block finalized on-chain, this multisig
    // is still active (step 3)
    let new_active_yet_not_reporting_end_block =
      next_keys_activation_block_number + S::CONFIRMATIONS + S::TEN_MINUTES;
    if block_number < new_active_yet_not_reporting_end_block {
      return (LifetimeStage::Active, reporting_start_block);
    }

    // Step 4 details a further CONFIRMATIONS
    let new_active_and_used_for_change_end_block =
      new_active_yet_not_reporting_end_block + S::CONFIRMATIONS;
    if block_number < new_active_and_used_for_change_end_block {
      return (LifetimeStage::UsingNewForChange, reporting_start_block);
    }

    // Step 5 details a further 6 hours
    // 6 hours = 6 * 60 minutes = 6 * 6 * 10 minutes
    let new_active_and_forwarded_to_end_block =
      new_active_and_used_for_change_end_block + (6 * 6 * S::TEN_MINUTES);
    if block_number < new_active_and_forwarded_to_end_block {
      return (LifetimeStage::Forwarding, reporting_start_block);
    }

    // Step 6
    (LifetimeStage::Finishing, reporting_start_block)
  }
}
