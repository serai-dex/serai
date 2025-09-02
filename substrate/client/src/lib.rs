#[cfg(feature = "networks")]
pub mod networks;

#[cfg(feature = "serai")]
mod serai;
#[cfg(feature = "serai")]
pub use serai::*;

#[cfg(not(feature = "serai"))]
pub use serai_abi::primitives;

#[cfg(test)]
mod tests;
