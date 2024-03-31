mod plan;
pub use plan::*;

pub mod networks;

pub(crate) mod multisigs {
  pub(crate) mod scheduler {
    use crate::networks::Network;

    pub trait Scheduler<N: Network>: PartialEq + core::fmt::Debug {}

    pub(crate) mod utxo {
      use crate::networks::Network;

      #[derive(PartialEq, Debug)]
      pub struct Scheduler<N>(core::marker::PhantomData<N>);
      impl<N: Network> crate::multisigs::scheduler::Scheduler<N> for Scheduler<N> {}
    }
  }
}

mod additional_key;
pub use additional_key::additional_key;
