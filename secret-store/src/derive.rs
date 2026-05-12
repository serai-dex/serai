use core::ops::Deref as _;
use std::collections::HashMap;

use zeroize::Zeroizing;
use blake2::{
  digest::{Update as _, FixedOutput as _},
  Blake2bMac512,
};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use ciphersuite::group::{
  ff::{PrimeField as _, FromUniformBytes as _},
  Group as _, GroupEncoding as _,
};

use super::hex;

type Context = Vec<(String, String)>;
type ServiceSecrets = Vec<(String, Zeroizing<String>)>;
type Secrets = HashMap<String, ServiceSecrets>;

/// Derive the secrets for the Message Queue.
fn message_queue(_context: &mut Context, _entropy: Blake2bMac512) -> ServiceSecrets {
  // This does not have any secrets of its own
  vec![]
}

/// Derive the secrets for the Processor.
fn processor(context: &mut Context, mut entropy: Blake2bMac512, network: &str) -> ServiceSecrets {
  entropy.update(b"/processor");
  entropy.update(format!("/{network}").as_bytes());

  let mut secrets = vec![];

  // Message Queue Key Pair
  {
    let mut message_queue = entropy.clone();
    message_queue.update(b"/message-queue");

    let message_queue =
      curve25519_dalek::Scalar::from_bytes_mod_order_wide(&message_queue.finalize_fixed().into());
    let message_queue_pub = RISTRETTO_BASEPOINT_TABLE * &message_queue;

    context.push((
      format!("PROCESSOR_{}_MESSAGE_QUEUE", network.to_uppercase()),
      hex::encode(message_queue_pub.compress().as_bytes()),
    ));
    secrets
      .push(("MESSAGE_QUEUE".to_owned(), Zeroizing::new(hex::encode(&message_queue.to_bytes()))));
  }

  // Auxiliary Keys
  {
    let mut entropy = entropy.clone();
    entropy.update(b"/auxiliary");

    // Substrate Auxiliary Key
    {
      let mut substrate = entropy.clone();
      substrate.update(b"/substrate");

      let key = embedwards25519::Scalar::from_uniform_bytes(&substrate.finalize_fixed().into());
      let pub_key = embedwards25519::Point::generator() * key;

      context.push((
        format!("PROCESSOR_{}_SUBSTRATE_AUXILIARY_KEY", network.to_uppercase()),
        hex::encode(&pub_key.to_bytes()),
      ));
      secrets.push((
        "SUBSTRATE_AUXILIARY_KEY".to_owned(),
        Zeroizing::new(hex::encode(key.to_repr().as_ref())),
      ));
    }

    // Network-specific Auxiliary Key
    {
      let mut substrate = entropy.clone();
      substrate.update(b"/network");

      let mut key_possibly_with_trailing_zeroes = [0; 32];
      let mut pub_key_possibly_with_trailing_zeroes = [0; 33];
      let (key, pub_key) = match network {
        "bitcoin" | "ethereum" => {
          let key = secq256k1::Scalar::from_uniform_bytes(&substrate.finalize_fixed().into());
          let pub_key = (secq256k1::Point::generator() * key).to_bytes();
          let key = key.to_repr();
          let key: &[u8] = key.as_ref();

          key_possibly_with_trailing_zeroes[.. key.len()].copy_from_slice(key);
          pub_key_possibly_with_trailing_zeroes[.. pub_key.len()].copy_from_slice(&pub_key);

          (
            &key_possibly_with_trailing_zeroes[.. key.len()],
            &pub_key_possibly_with_trailing_zeroes[.. pub_key.len()],
          )
        }
        // Because these networks have the same elliptic curve for their auxiliary keys as used for
        // Substrate, the auxiliary key itself is reused (as the invocations are domain-separated)
        "monero" => {
          let substrate_auxiliary_pub_key = context.last().unwrap();
          assert_eq!(
            &substrate_auxiliary_pub_key.0,
            &format!("PROCESSOR_{}_SUBSTRATE_AUXILIARY_KEY", network.to_uppercase())
          );
          let pub_key_len = substrate_auxiliary_pub_key.1.len() / 2;
          hex::decode(
            substrate_auxiliary_pub_key.1.as_bytes(),
            &mut pub_key_possibly_with_trailing_zeroes[.. pub_key_len],
          )
          .unwrap();

          let substrate_auxiliary_key = secrets.last().unwrap();
          assert_eq!(&substrate_auxiliary_key.0, "SUBSTRATE_AUXILIARY_KEY");
          let key_len = substrate_auxiliary_key.1.len() / 2;
          hex::decode(
            substrate_auxiliary_key.1.as_bytes(),
            &mut key_possibly_with_trailing_zeroes[.. key_len],
          )
          .unwrap();

          (
            &key_possibly_with_trailing_zeroes[.. key_len],
            &pub_key_possibly_with_trailing_zeroes[.. pub_key_len],
          )
        }
        _ => panic!("asked to derive the network-specific auxiliary key for unknown network"),
      };

      context.push((
        format!("PROCESSOR_{}_NETWORK_AUXILIARY_KEY", network.to_uppercase()),
        hex::encode(pub_key),
      ));
      secrets.push(("NETWORK_AUXILIARY_KEY".to_owned(), Zeroizing::new(hex::encode(key))));
    }
  }

  secrets
}

fn coordinator(
  context: &mut Context,
  mut entropy: Blake2bMac512,
  serai_auxiliary_key: &Zeroizing<curve25519_dalek::Scalar>,
) -> ServiceSecrets {
  entropy.update(b"/coordinator");

  let mut secrets = vec![];

  // Message Queue Key Pair
  {
    let mut message_queue = entropy.clone();
    message_queue.update(b"/message-queue");

    let message_queue =
      curve25519_dalek::Scalar::from_bytes_mod_order_wide(&message_queue.finalize_fixed().into());
    let message_queue_pub = RISTRETTO_BASEPOINT_TABLE * &message_queue;

    context.push((
      "COORDINATOR_MESSAGE_QUEUE".to_owned(),
      hex::encode(message_queue_pub.compress().as_bytes()),
    ));
    secrets
      .push(("MESSAGE_QUEUE".to_owned(), Zeroizing::new(hex::encode(&message_queue.to_bytes()))));
  }

  // Validator Key
  secrets.push((
    "SERAI_AUXILIARY_KEY".to_owned(),
    Zeroizing::new(hex::encode(&serai_auxiliary_key.to_bytes())),
  ));

  secrets
}

#[expect(clippy::vec_init_then_push)]
fn serai_node(
  _context: &mut Context,
  mut entropy: Blake2bMac512,
  serai_auxiliary_key: &Zeroizing<curve25519_dalek::Scalar>,
) -> ServiceSecrets {
  entropy.update(b"/serai-node");

  let mut secrets = vec![];

  // Validator Key
  secrets.push((
    "SERAI_AUXILIARY_KEY".to_owned(),
    Zeroizing::new(hex::encode(&serai_auxiliary_key.to_bytes())),
  ));

  secrets
}

#[expect(clippy::needless_pass_by_value)]
pub(super) fn context_and_secrets(entropy: Zeroizing<[u8; 32]>) -> (Context, Secrets) {
  let entropy = Blake2bMac512::new_with_salt_and_personal(entropy.as_slice(), &[], &[]).unwrap();

  let mut context = vec![];
  let mut secrets = HashMap::new();

  secrets.insert("MESSAGE_QUEUE".to_owned(), message_queue(&mut context, entropy.clone()));

  for network in super::external_networks() {
    secrets.insert(
      format!("PROCESSOR_{}", network.to_uppercase()),
      processor(&mut context, entropy.clone(), network),
    );
  }

  let serai_auxiliary_key = Zeroizing::new({
    let mut serai_auxiliary_key = entropy.clone();
    serai_auxiliary_key.update(b"/serai/auxiliary");
    curve25519_dalek::Scalar::from_bytes_mod_order_wide(
      &serai_auxiliary_key.finalize_fixed().into(),
    )
  });
  {
    context.push((
      "SERAI_AUXILIARY_KEY".to_owned(),
      hex::encode(&(RISTRETTO_BASEPOINT_TABLE * serai_auxiliary_key.deref()).compress().to_bytes()),
    ));
  }

  // TODO: Should the Serai node, Coordinator, also share a P2P key?
  // https://github.com/serai-dex/serai/issues/822

  secrets.insert(
    "COORDINATOR".to_owned(),
    coordinator(&mut context, entropy.clone(), &serai_auxiliary_key),
  );

  secrets.insert(
    "SERAI_NODE".to_owned(),
    serai_node(&mut context, entropy.clone(), &serai_auxiliary_key),
  );

  // TODO: `zeroize::zeroize_stack`

  (context, secrets)
}
