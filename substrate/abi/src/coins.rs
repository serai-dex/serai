use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  address::SeraiAddress, balance::Balance, instructions::OutInstructionWithBalance,
};

/// A call to coins.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Call {
  /// Transfer these coins to the specified address.
  transfer {
    /// The address to transfer to.
    to: SeraiAddress,
    /// The coins to transfer.
    coins: Balance,
  },
  /// Burn these coins.
  burn {
    /// The coins to burn.
    coins: Balance,
  },
  /// Burn these coins with an `OutInstruction` specified.
  burn_with_instruction {
    /// The `OutInstruction`, with the coins to burn.
    instruction: OutInstructionWithBalance,
  },
}

impl Call {
  pub(crate) fn is_signed(&self) -> bool {
    match self {
      Call::transfer { .. } | Call::burn { .. } | Call::burn_with_instruction { .. } => true,
    }
  }
}

/// An event from the system.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Event {
  /// The specified coins were minted.
  Mint {
    /// The address minted to.
    to: SeraiAddress,
    /// The coins minted.
    coins: Balance,
  },
  /// The specified coins were burnt.
  Burn {
    /// The address burnt from.
    from: SeraiAddress,
    /// The coins burnt.
    coins: Balance,
  },
  /// The specified coins were burnt with an `OutInstruction` specified.
  BurnWithInstruction {
    /// The address burnt from.
    from: SeraiAddress,
    /// The `OutInstruction` specified, and the coins burnt.
    instruction: OutInstructionWithBalance,
  },
  /// The specified coins were transferred.
  Transfer {
    /// The address transferred from.
    from: SeraiAddress,
    /// The address transferred to.
    to: SeraiAddress,
    /// The coins transferred.
    coins: Balance,
  },
}
