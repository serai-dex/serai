#[cfg(feature = "bitcoin")]
pub use serai_client_bitcoin as bitcoin;
#[cfg(feature = "ethereum")]
pub mod serai_client_ethereum as ethereum;
#[cfg(feature = "monero")]
pub mod serai_client_monero as monero;

#[cfg(feature = "serai")]
pub use serai_client_serai as serai;

#[cfg(test)]
mod tests;
