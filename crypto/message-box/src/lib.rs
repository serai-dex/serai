#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use rand_core::OsRng;

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_TABLE, Scalar, ristretto::RistrettoPoint};

use chacha20::{Key, XChaCha20};

pub struct SecureMessage(Vec<u8>);

pub fn key_gen() -> (Scalar, RistrettoPoint) {
  let mut scalar;
  while {
    scalar = Scalar::random(&mut OsRng);
    scalar.is_zero()
  } {}
  (scalar, scalar * &RISTRETTO_BASEPOINT_TABLE)
}

pub struct MessageBox {
  our_key: Scalar,
  // Optimization for later transcripting
  our_public_key: RistrettoPoint,
  // When generating nonces, we transcript additional entropy to hedge against weak randomness
  // This is primarily the private key, yet also an early set of bytes from the OsRng which may
  // have a higher quality entropy than latter calls
  // Instead of constantly passing around the private key bytes/early RNG, littering memory with
  // copies, store a copy which is already hashed
  additional_entropy: [u8; 64],
  enc_keys: HashMap<&'static str, Key>
}

impl MessageBox {
  pub fn new(our_name: &'static str, our_key: Scalar, keys: HashMap<&'static str, RistrettoPoint>) -> MessageBox {
    let transcript = || {
      let mut transcript = RecommendedTranscript::new(b"MessageBox");
      transcript.domain_separate(b"encryption_keys");
      transcript
    };

    MessageBox {
      enc_keys: keys.drain(..).map(|(other_name, other_key)| {
        let mut transcript = transcript();

        let (name_a, name_b) = match our_name.cmp(other_name) {
          Ordering::Less => (our_name, other_name),
          Ordering::Equal => panic!("encrypting to ourself"),
          Ordering::Greater => (other_name, our_name),
        };
        transcript.append_message(b"name_a", name_a);
        transcript.append_message(b"name_b", name_b);

        transcript.append_message(b"shared_key", &(our_key * other_key).to_bytes());
        let shared_key = transcript.challenge("encryption_key");

        let mut key = Key::default();
        key.copy_from_slice(shared_key[.. 32]);

        (other_name, key)
      }).collect(),

      our_key,
      our_public_key: our_key * &RISTRETTO_BASEPOINT_TABLE,

      additional_entropy: {
        let mut transcript = RecommendedTranscript::new(b"MessageBox");
        transcript.domain_separate("key_hash");
        transcript.append_message(b"private_key", &our_key.to_bytes());

        // This is exceptionally redundant and arguably pointless
        {
          let mut bytes = [0; 64];
          rng.fill_bytes(&mut bytes);
          transcript.append_message(b"rng", &bytes.to_bytes());
        }
        transcript.challenge(b"key_hash").into()
      },
    }
  }

  pub fn encrypt(&self, to: &'static str, mut msg: Vec<u8>) -> SecureMessage {
    let mut iv = XNonce::default();
    OsRng.fill_bytes(iv.as_mut());
    XChaCha20::new(self.enc_keys[to], &iv).apply_keystream(msg.as_ref());

    let nonce = {
      let mut transcript = RecommendedTranscript::new(b"MessageBox");
      transcript.domain_separate(b"nonce");
      transcript.domain_separate(b"additional_entropy", &self.additional_entropy);
      transcript.domain_separate(b"public_key", self.our_public_key.to_bytes());
      transcript.domain_separate(b"message", &msg);
      Scalar::from_bytes_mod_order(transcript.challenge(b"nonce").into());
    };
    #[allow(non_snake_case)]
    let R = nonce * &RISTRETTO_BASEPOINT_TABLE;

    let mut transcript = RecommendedTranscript::new(b"MessageBox");
    transcript.domain_separate(b"signature");
    transcript.append_message(b"nonce", R.to_bytes());
    transcript.append_message(b"public_key", self.our_public_key);
    transcript.domain_separate(b"message");
    transcript.append_message(b"iv", iv.as_ref());
    transcript.append_message(b"encrypted_message", &msg);
    let challenge = Scalar::from_bytes_mod_order(transcript.challenge(b"message_signature").into());

    let sig = SchnorrSignature::sign(self.our_key, nonce, challenge);

    msg.extend(nonce.as_ref());
    sig.write(&mut msg);

    SecureMessage(msg)
  }

  pub fn decrypt(&self, from: &'static str, msg: SecureMessage) -> Vec<u8> {
    
  }
}
