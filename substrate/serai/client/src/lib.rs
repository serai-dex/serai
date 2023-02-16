#[cfg(feature = "coins")]
pub mod coins;

#[cfg(feature = "serai")]
mod serai;
#[cfg(feature = "serai")]
pub use serai::*;

// If we aren't exposing the Serai client (subxt), still expose all primitives
#[cfg(not(feature = "serai"))]
pub use serai_runtime::primitives;
#[cfg(not(feature = "serai"))]
mod other_primitives {
  pub mod in_instructions {
    pub use serai_runtime::in_instructions::primitives;
  }
  pub mod tokens {
    pub use serai_runtime::tokens::primitives;
  }
  pub mod validator_sets {
    pub use serai_runtime::validator_sets::primitives;
  }
}
#[cfg(not(feature = "serai"))]
pub use other_primitives::*;

#[cfg(test)]
mod tests;
