use core::ops::Deref;

use std::collections::HashMap;
#[cfg(test)]
use std::str::FromStr;

use zeroize::Zeroizing;

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use ciphersuite::group::{ff::PrimeField, GroupEncoding};

use crate::{
  curve::Curve,
  Participant, ThresholdCore, ThresholdKeys,
  algorithm::{Hram, IetfSchnorr},
  sign::{
    Writable, Nonce, GeneratorCommitments, NonceCommitments, Commitments, Preprocess,
    PreprocessMachine, SignMachine, SignatureMachine, AlgorithmMachine,
  },
  tests::{clone_without, recover_key, test_ciphersuite},
};

/// Vectors for a ciphersuite.
pub struct Vectors {
  pub threshold: u16,

  pub group_secret: String,
  pub group_key: String,
  pub shares: Vec<String>,

  pub msg: String,
  pub included: Vec<Participant>,

  pub nonce_randomness: Vec<[String; 2]>,
  pub nonces: Vec<[String; 2]>,
  pub commitments: Vec<[String; 2]>,

  pub sig_shares: Vec<String>,

  pub sig: String,
}

// Vectors are expected to be formatted per the IETF proof of concept
// The included vectors are directly from
// https://github.com/cfrg/draft-irtf-cfrg-frost/tree/draft-irtf-cfrg-frost-14/poc
#[cfg(test)]
impl From<serde_json::Value> for Vectors {
  fn from(value: serde_json::Value) -> Vectors {
    let to_str = |value: &serde_json::Value| value.as_str().unwrap().to_string();
    Vectors {
      threshold: u16::from_str(value["config"]["NUM_PARTICIPANTS"].as_str().unwrap()).unwrap(),

      group_secret: to_str(&value["inputs"]["group_secret_key"]),
      group_key: to_str(&value["inputs"]["group_public_key"]),
      shares: value["inputs"]["participant_shares"]
        .as_array()
        .unwrap()
        .iter()
        .map(|share| to_str(&share["participant_share"]))
        .collect(),

      msg: to_str(&value["inputs"]["message"]),
      included: value["inputs"]["participant_list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| Participant::new(u16::try_from(i.as_u64().unwrap()).unwrap()).unwrap())
        .collect(),

      nonce_randomness: value["round_one_outputs"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
          [to_str(&value["hiding_nonce_randomness"]), to_str(&value["binding_nonce_randomness"])]
        })
        .collect(),
      nonces: value["round_one_outputs"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| [to_str(&value["hiding_nonce"]), to_str(&value["binding_nonce"])])
        .collect(),
      commitments: value["round_one_outputs"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
          [to_str(&value["hiding_nonce_commitment"]), to_str(&value["binding_nonce_commitment"])]
        })
        .collect(),

      sig_shares: value["round_two_outputs"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| to_str(&value["sig_share"]))
        .collect(),

      sig: to_str(&value["final_output"]["sig"]),
    }
  }
}

// Load these vectors into ThresholdKeys using a custom serialization it'll deserialize
fn vectors_to_multisig_keys<C: Curve>(vectors: &Vectors) -> HashMap<Participant, ThresholdKeys<C>> {
  let shares = vectors
    .shares
    .iter()
    .map(|secret| C::read_F::<&[u8]>(&mut hex::decode(secret).unwrap().as_ref()).unwrap())
    .collect::<Vec<_>>();
  let verification_shares = shares.iter().map(|secret| C::generator() * secret).collect::<Vec<_>>();

  let mut keys = HashMap::new();
  for i in 1 ..= u16::try_from(shares.len()).unwrap() {
    // Manually re-implement the serialization for ThresholdCore to import this data
    let mut serialized = vec![];
    serialized.extend(u32::try_from(C::ID.len()).unwrap().to_le_bytes());
    serialized.extend(C::ID);
    serialized.extend(vectors.threshold.to_le_bytes());
    serialized.extend(u16::try_from(shares.len()).unwrap().to_le_bytes());
    serialized.extend(i.to_le_bytes());
    serialized.push(1);
    serialized.extend(shares[usize::from(i) - 1].to_repr().as_ref());
    for share in &verification_shares {
      serialized.extend(share.to_bytes().as_ref());
    }

    let these_keys = ThresholdCore::<C>::read::<&[u8]>(&mut serialized.as_ref()).unwrap();
    assert_eq!(these_keys.params().t(), vectors.threshold);
    assert_eq!(usize::from(these_keys.params().n()), shares.len());
    let participant = Participant::new(i).unwrap();
    assert_eq!(these_keys.params().i(), participant);
    assert_eq!(these_keys.secret_share().deref(), &shares[usize::from(i - 1)]);
    assert_eq!(hex::encode(these_keys.group_key().to_bytes().as_ref()), vectors.group_key);
    keys.insert(participant, ThresholdKeys::new(these_keys));
  }

  keys
}

/// Test a Ciphersuite with its vectors.
pub fn test_with_vectors<R: RngCore + CryptoRng, C: Curve, H: Hram<C>>(
  rng: &mut R,
  vectors: &Vectors,
) {
  test_ciphersuite::<R, C, H>(rng);

  // Test against the vectors
  let keys = vectors_to_multisig_keys::<C>(vectors);
  {
    let group_key =
      <C as Curve>::read_G::<&[u8]>(&mut hex::decode(&vectors.group_key).unwrap().as_ref())
        .unwrap();
    let secret =
      C::read_F::<&[u8]>(&mut hex::decode(&vectors.group_secret).unwrap().as_ref()).unwrap();
    assert_eq!(C::generator() * secret, group_key);
    assert_eq!(recover_key(&keys), secret);

    let mut machines = vec![];
    for i in &vectors.included {
      machines.push((i, AlgorithmMachine::new(IetfSchnorr::<C, H>::ietf(), keys[i].clone())));
    }

    let mut commitments = HashMap::new();
    let machines = machines
      .into_iter()
      .enumerate()
      .map(|(c, (i, machine))| {
        let nonce = |i| {
          Zeroizing::new(
            C::read_F::<&[u8]>(&mut hex::decode(&vectors.nonces[c][i]).unwrap().as_ref()).unwrap(),
          )
        };
        let nonces = [nonce(0), nonce(1)];
        let these_commitments =
          [C::generator() * nonces[0].deref(), C::generator() * nonces[1].deref()];

        assert_eq!(
          these_commitments[0].to_bytes().as_ref(),
          hex::decode(&vectors.commitments[c][0]).unwrap()
        );
        assert_eq!(
          these_commitments[1].to_bytes().as_ref(),
          hex::decode(&vectors.commitments[c][1]).unwrap()
        );

        let preprocess = Preprocess {
          commitments: Commitments {
            nonces: vec![NonceCommitments {
              generators: vec![GeneratorCommitments(these_commitments)],
            }],
          },
          addendum: (),
        };
        // FROST doesn't specify how to serialize these together, yet this is sane
        // (and the simplest option)
        assert_eq!(
          preprocess.serialize(),
          hex::decode(vectors.commitments[c][0].clone() + &vectors.commitments[c][1]).unwrap()
        );

        let machine = machine.unsafe_override_preprocess(vec![Nonce(nonces)], preprocess);

        commitments.insert(
          *i,
          machine
            .read_preprocess::<&[u8]>(
              &mut [
                these_commitments[0].to_bytes().as_ref(),
                these_commitments[1].to_bytes().as_ref(),
              ]
              .concat()
              .as_ref(),
            )
            .unwrap(),
        );
        (i, machine)
      })
      .collect::<Vec<_>>();

    let mut shares = HashMap::new();
    let machines = machines
      .into_iter()
      .enumerate()
      .map(|(c, (i, machine))| {
        let (machine, share) = machine
          .sign(clone_without(&commitments, i), &hex::decode(&vectors.msg).unwrap())
          .unwrap();

        let share = {
          let mut buf = vec![];
          share.write(&mut buf).unwrap();
          buf
        };
        assert_eq!(share, hex::decode(&vectors.sig_shares[c]).unwrap());

        shares.insert(*i, machine.read_share::<&[u8]>(&mut share.as_ref()).unwrap());
        (i, machine)
      })
      .collect::<Vec<_>>();

    for (i, machine) in machines {
      let sig = machine.complete(clone_without(&shares, i)).unwrap();
      let mut serialized = sig.R.to_bytes().as_ref().to_vec();
      serialized.extend(sig.s.to_repr().as_ref());
      assert_eq!(hex::encode(serialized), vectors.sig);
    }
  }

  // The above code didn't test the nonce generation due to the infeasibility of doing so against
  // the current codebase

  // A transparent RNG which has a fixed output
  struct TransparentRng(Vec<[u8; 32]>);
  impl RngCore for TransparentRng {
    fn next_u32(&mut self) -> u32 {
      unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
      unimplemented!()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
      dest.copy_from_slice(&self.0.remove(0))
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
      unimplemented!()
    }
  }
  // CryptoRng requires the output not reveal any info about any other outputs
  // Since this only will produce one output, this is actually met, even though it'd be fine to
  // fake it as this is a test
  impl CryptoRng for TransparentRng {}

  // Test C::random_nonce matches the expected vectors
  for (i, l) in vectors.included.iter().enumerate() {
    let l = usize::from(u16::from(*l));

    // Shares are a zero-indexed array of all participants, hence l - 1
    let share = Zeroizing::new(
      C::read_F::<&[u8]>(&mut hex::decode(&vectors.shares[l - 1]).unwrap().as_ref()).unwrap(),
    );

    let randomness = vectors.nonce_randomness[i]
      .iter()
      .map(|randomness| hex::decode(randomness).unwrap().try_into().unwrap())
      .collect::<Vec<_>>();

    let nonces = vectors.nonces[i]
      .iter()
      .map(|nonce| {
        Zeroizing::new(C::read_F::<&[u8]>(&mut hex::decode(nonce).unwrap().as_ref()).unwrap())
      })
      .collect::<Vec<_>>();

    for (randomness, nonce) in randomness.iter().zip(&nonces) {
      // Nonces are only present for participating signers, hence i
      assert_eq!(C::random_nonce(&share, &mut TransparentRng(vec![*randomness])), *nonce);
    }

    // Also test it at the Commitments level
    let (generated_nonces, commitments) =
      Commitments::<C>::new::<_>(&mut TransparentRng(randomness), &share, &[vec![C::generator()]]);

    assert_eq!(generated_nonces.len(), 1);
    assert_eq!(generated_nonces[0].0, [nonces[0].clone(), nonces[1].clone()]);

    let mut commitments_bytes = vec![];
    commitments.write(&mut commitments_bytes).unwrap();
    assert_eq!(
      commitments_bytes,
      hex::decode(vectors.commitments[i][0].clone() + &vectors.commitments[i][1]).unwrap()
    );
  }

  // This doesn't verify C::random_nonce is called correctly, where the code should call it with
  // the output from a ChaCha20 stream
  // Create a known ChaCha20 stream to verify it ends up at random_nonce properly

  {
    let mut chacha_seed = [0; 32];
    rng.fill_bytes(&mut chacha_seed);
    let mut ours = ChaCha20Rng::from_seed(chacha_seed);
    let frosts = ours.clone();

    // The machines should geenerate a seed, and then use that seed in a ChaCha20 RNG for nonces
    let mut preprocess_seed = [0; 32];
    ours.fill_bytes(&mut preprocess_seed);
    let mut ours = ChaCha20Rng::from_seed(preprocess_seed);

    // Get the randomness which will be used
    let mut randomness = ([0; 32], [0; 32]);
    ours.fill_bytes(&mut randomness.0);
    ours.fill_bytes(&mut randomness.1);

    // Create the machines
    let mut machines = vec![];
    for i in &vectors.included {
      machines.push((i, AlgorithmMachine::new(IetfSchnorr::<C, H>::ietf(), keys[i].clone())));
    }

    for (i, machine) in machines {
      let (_, preprocess) = machine.preprocess(&mut frosts.clone());

      // Calculate the expected nonces
      let mut expected = (C::generator() *
        C::random_nonce(keys[i].secret_share(), &mut TransparentRng(vec![randomness.0])).deref())
      .to_bytes()
      .as_ref()
      .to_vec();
      expected.extend(
        (C::generator() *
          C::random_nonce(keys[i].secret_share(), &mut TransparentRng(vec![randomness.1]))
            .deref())
        .to_bytes()
        .as_ref(),
      );

      // Ensure they match
      assert_eq!(preprocess.serialize(), expected);
    }
  }
}
