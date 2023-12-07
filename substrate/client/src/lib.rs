#[cfg(feature = "networks")]
pub mod networks;

#[cfg(feature = "serai")]
mod serai;
#[cfg(feature = "serai")]
pub use serai::*;

#[cfg(not(feature = "serai"))]
pub use serai_abi::primitives;
#[cfg(not(feature = "serai"))]
mod other_primitives {
  pub mod coins {
    pub use serai_abi::coins::primitives;
  }
  pub mod validator_sets {
    pub use serai_abi::validator_sets::primitives;
  }
  pub mod in_instructions {
    pub use serai_abi::in_instructions::primitives;
  }
}
#[cfg(not(feature = "serai"))]
pub use other_primitives::*;

#[cfg(test)]
mod tests;
