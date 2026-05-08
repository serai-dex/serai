/// Ed25519, and an elliptic curve defined over its scalar field (embedwards25519).
pub struct Ed25519;
impl dkg::Curves for Ed25519 {
  type ToweringCurve = dalek_ff_group::Ed25519;
  type EmbeddedCurve = embedwards25519::Embedwards25519;
  type EmbeddedCurveParameters = embedwards25519::Embedwards25519;
}

pub(crate) struct KeyGenParams;
impl key_gen::KeyGenParams for KeyGenParams {
  const ID: &'static str = "Monero";

  type ExternalNetworkCiphersuite = Ed25519;
}
