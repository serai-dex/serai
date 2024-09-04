#[allow(clippy::type_complexity)]
#[derive(Clone, Debug)]
pub enum MultisigEvent<N: Network> {
  // Batches to publish
  Batches(Option<(<N::Curve as Ciphersuite>::G, <N::Curve as Ciphersuite>::G)>, Vec<Batch>),
  // Eventuality completion found on-chain
  Completed(Vec<u8>, [u8; 32], <N::Eventu
}
