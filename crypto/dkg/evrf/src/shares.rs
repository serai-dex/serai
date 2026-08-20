use ciphersuite::group::ff::{Field, FromUniformBytes as _};

use super::*;

/// Sample a random `k'` for a recipient's public key.
///
/// Per the eVRF paper, the sum of the two `x` coordinates is a _weighted_ sum, with `k'` used to
/// weight the second `x` coordinate to achieve a uniform result. During key generation, a
/// participant is expected to sample and publish a random uniform `k'`.
///
/// Instead of extending the communicated length of the verification key, as `k'` is public, we
/// fix the derivation of `k' = H_{k'}(public_key)`. By treating `H_{k'}` as a random oracle, the
/// result is still a random, uniform value suitable for our purposes.
pub(crate) fn k_prime<C: Curves>(
  public_key: &<C::EmbeddedCurve as WrappedGroup>::G,
) -> <C::ToweringCurve as WrappedGroup>::F {
  use blake2::{
    digest::{array::Array, common::KeySizeUser, KeyInit, Mac as _},
    Blake2bMac512,
  };

  <C::ToweringCurve as WrappedGroup>::F::from_uniform_bytes(
    &<Blake2bMac512 as KeyInit>::new(&{
      let mut key = Array::<u8, <Blake2bMac512 as KeySizeUser>::KeySize>::default();
      {
        let key: &mut [u8] = key.as_mut();
        key[.. 2].copy_from_slice(b"k'");
      }
      key
    })
    .chain_update(public_key.to_bytes())
    .finalize()
    .into_bytes()
    .into(),
  )
}

/// The scalars which would be used by a Shamir-secret sharing.
///
/// `weight` may be specified as a linear factor applied to all of the following scalars. This
/// is intended to enable usage for batch verification.
fn shamir_secret_sharing_scalars<F: Field>(i: F, t: usize, weight: F) -> impl Iterator<Item = F> {
  // `weight * [i^0, ..., i^{t - 1}]`
  (0 .. t).scan(weight, move |exp, _| {
    let result = Some(*exp);
    *exp *= i;
    result
  })
}

/// Batch-verifiable statements to verify encrypted secret shares.
fn verifiable_encryption_statements<ToweringCurve: WrappedGroup>(
  rng: &mut (impl RngCore + CryptoRng),
  coefficients: &[ToweringCurve::G],
  encryption_key_commitments: &[ToweringCurve::G],
  encrypted_secret_shares: &HashMap<Participant, ToweringCurve::F>,
) -> Vec<(ToweringCurve::F, ToweringCurve::G)> {
  let mut g_scalar = ToweringCurve::F::ZERO;
  let mut pairs = Vec::with_capacity(coefficients.len() + encryption_key_commitments.len());

  // Push on the commitments to the polynomial being secret-shared
  for coefficient in coefficients {
    // This uses `0` as we'll add to it later, given its fixed position
    pairs.push((ToweringCurve::F::ZERO, *coefficient));
  }

  for (i, encrypted_secret_share) in encrypted_secret_shares {
    let i = u16::from(*i);
    let weight = ToweringCurve::F::random(&mut *rng);

    // Calculate the commitment to the secret share via the commitments to the polynomial
    {
      let i = ToweringCurve::F::from(u64::from(i));
      // This is premised on how the coefficients are _first_ in our vector of `pairs`
      for (scalar, commitment) in
        shamir_secret_sharing_scalars(i, coefficients.len(), weight).zip(&mut pairs)
      {
        commitment.0 += scalar;
      }
    }

    // Push the (weighted) commitment to the mask
    pairs.push((weight, encryption_key_commitments[usize::from(i) - 1]));

    // The sum of the commitment to the message, commitment to the mask should equal the sum of
    // the message and mask (the ciphertext) scalaring the commitment generator
    g_scalar -= weight * encrypted_secret_share;
  }

  pairs.push((g_scalar, ToweringCurve::generator()));

  pairs
}

pub(super) struct EncryptedSecretShare<C: Curves> {
  ecdh_commitments: [<C::EmbeddedCurve as WrappedGroup>::G; 2],
  encrypted_secret_share: <C::ToweringCurve as WrappedGroup>::F,
}
impl<C: Curves> Clone for EncryptedSecretShare<C> {
  fn clone(&self) -> Self {
    *self
  }
}
impl<C: Curves> Copy for EncryptedSecretShare<C> {}

impl<C: Curves> EncryptedSecretShare<C> {
  /// Decrypt an encrypted secret share.
  ///
  /// This assumes the validity of the encrypted secret share. This has undefined behavior if
  /// any ECDH is/would be the identity point.
  pub(super) fn decrypt(
    self,
    evrf_private_key: &Zeroizing<<C::EmbeddedCurve as WrappedGroup>::F>,
  ) -> Zeroizing<<C::ToweringCurve as WrappedGroup>::F> {
    let Self { ecdh_commitments, encrypted_secret_share } = self;

    let [ecdh_commitment_0, ecdh_commitment_1] = ecdh_commitments;
    let mut secret_share = Zeroizing::new(encrypted_secret_share);
    for (weight, ecdh_commitment) in [
      (<C::ToweringCurve as WrappedGroup>::F::ONE, ecdh_commitment_0),
      (
        k_prime::<C>(&(<C::EmbeddedCurve as WrappedGroup>::generator() * evrf_private_key.deref())),
        ecdh_commitment_1,
      ),
    ] {
      let (mut x, mut y) =
        <C::EmbeddedCurve as WrappedGroup>::G::to_xy(ecdh_commitment * evrf_private_key.deref())
          .unwrap();
      *secret_share -= weight * x;
      x.zeroize();
      y.zeroize();
    }
    secret_share
  }
}

pub(super) struct Verified<C: Curves> {
  pub(super) verification_shares: HashMap<Participant, <C::ToweringCurve as WrappedGroup>::G>,
  /// These are `(from, (to, share))`.
  pub(super) encrypted_secret_shares:
    HashMap<Participant, HashMap<Participant, EncryptedSecretShare<C>>>,
}

/// Verify a set of encrypted secret shares.
///
/// This solely verifies the encrypted secret share corresponds to the proof's commitments for the
/// coefficients, masks. As it inputs a [`crate::proof::Verified`], this trusts those to be
/// accurate.
///
/// This only returns `None` if a potentially valid participation was invalid.
#[expect(clippy::type_complexity)]
pub(super) fn verify<C: Curves>(
  rng: &mut (impl RngCore + CryptoRng),
  generators: &Generators<C>,
  t: u16,
  n: u16,
  evrf_public_keys: &[<C::EmbeddedCurve as WrappedGroup>::G],
  potentially_valid: &mut HashMap<
    Participant,
    (HashMap<Participant, <C::ToweringCurve as WrappedGroup>::F>, crate::proof::Verified<C>),
  >,
  faulty: &mut HashSet<Participant>,
) -> Option<Verified<C>> {
  // Perform the batch verification of the shares
  let mut sum_encrypted_secret_shares = HashMap::with_capacity(usize::from(n));
  let mut sum_masks = HashMap::with_capacity(usize::from(n));
  let mut all_encrypted_secret_shares = HashMap::with_capacity(usize::from(t));

  {
    let mut share_verification_statements = HashMap::with_capacity(potentially_valid.len());
    if !{
      let mut pairs =
        Vec::with_capacity(potentially_valid.len() * (usize::from(t) + evrf_public_keys.len()));
      for (i, (encrypted_secret_shares, data)) in &*potentially_valid {
        let these_pairs = verifiable_encryption_statements::<C::ToweringCurve>(
          &mut *rng,
          &data.coefficients,
          &data.encryption_key_commitments,
          encrypted_secret_shares,
        );
        // Queue this into our batch
        pairs.extend(&these_pairs);

        // Also track these individually in case we have to perform a blame protocol
        assert!(share_verification_statements.insert(*i, these_pairs).is_none());

        // Also format this data as we'd need it upon success
        let mut formatted_encrypted_secret_shares = HashMap::with_capacity(usize::from(n));
        for (j, enc_share) in encrypted_secret_shares {
          /*
            We calculate verification shares as the sum of the encrypted scalars, minus their
            masks. This only does one scalar multiplication, and `1+t` point additions (with
            one negation), and is accordingly much cheaper than interpolating the commitments.
            This is only possible because we already interpolated the commitments to verify the
            encrypted secret share.
          */
          *sum_encrypted_secret_shares
            .entry(*j)
            .or_insert(<C::ToweringCurve as WrappedGroup>::F::ZERO) += enc_share;
          let j_index = usize::from(u16::from(*j)) - 1;
          *sum_masks.entry(*j).or_insert(<C::ToweringCurve as WrappedGroup>::G::identity()) +=
            data.encryption_key_commitments[j_index];

          assert!(
            formatted_encrypted_secret_shares
              .insert(
                *j,
                EncryptedSecretShare {
                  ecdh_commitments: data.ecdh_commitments[j_index],
                  encrypted_secret_share: *enc_share,
                },
              )
              .is_none()
          );
        }
        assert!(
          all_encrypted_secret_shares.insert(*i, formatted_encrypted_secret_shares).is_none()
        );
      }
      bool::from(multiexp_vartime(&pairs).is_identity())
    } {
      // If the batch failed, verify them each individually
      for (i, pairs) in share_verification_statements {
        if !bool::from(multiexp_vartime(&pairs).is_identity()) {
          assert!(potentially_valid.remove(&i).is_some());
          assert!(faulty.insert(i));
        }
      }
      /*
        Because some entries were invalid, corrupting our sums, return nothing as verified.

        Alternatively, as `potentially_valid` is now accurate, we could recursively call ourselves
        once (as the inner call is guaranteed) to succeed to obtain a correct instance of
        `Verified`. As the `Dkg` which calls this won't yield any result if any participations are
        invalid, the time, effort, and complexity would be wasted.
      */
      None?;
    }
  }

  // Calculate each participant's verification share
  let mut verification_shares = HashMap::with_capacity(usize::from(n));
  if !potentially_valid.is_empty() {
    for i in Participant::iter().take(usize::from(n)) {
      assert!(
        verification_shares
          .insert(i, (generators.0.g() * sum_encrypted_secret_shares[&i]) - sum_masks[&i])
          .is_none()
      );
    }
  }

  Some(Verified { verification_shares, encrypted_secret_shares: all_encrypted_secret_shares })
}

#[test]
fn batch_verification() {
  use rand_core::OsRng;

  for participants in 1 ..= 5 {
    for threshold in 1 ..= 3.min(participants) {
      let mut coefficients = vec![];
      for _ in 0 .. threshold {
        coefficients.push(Zeroizing::new(
          <<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::F::random(&mut OsRng),
        ));
      }

      let mut encryption_keys = vec![];
      for _ in 0 .. participants {
        encryption_keys
          .push(<<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::F::random(&mut OsRng));
      }

      let mut encrypted_secret_shares = HashMap::new();
      for i in Participant::iter().take(participants) {
        let secret_share = crate::polynomial(&coefficients, i);
        assert!(
          encrypted_secret_shares
            .insert(i, *secret_share + encryption_keys[usize::from(u16::from(i)) - 1])
            .is_none()
        );
      }

      let coefficients = coefficients
        .into_iter()
        .map(|coeff| <<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::generator() * *coeff)
        .collect::<Vec<_>>();
      let encryption_key_commitments = encryption_keys
        .into_iter()
        .map(|key| <<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::generator() * key)
        .collect::<Vec<_>>();

      // This should work for an honest prover
      let statements = verifiable_encryption_statements::<<Ed25519 as Curves>::ToweringCurve>(
        &mut OsRng,
        &coefficients,
        &encryption_key_commitments,
        &encrypted_secret_shares,
      );
      assert!(bool::from(multiexp_vartime(&statements).is_identity()));

      // This should have a randomly assigned weight
      {
        let statements_2 = verifiable_encryption_statements::<<Ed25519 as Curves>::ToweringCurve>(
          &mut OsRng,
          &coefficients,
          &encryption_key_commitments,
          &encrypted_secret_shares,
        );
        assert!(bool::from(multiexp_vartime(&statements).is_identity()));
        assert_eq!(statements.len(), statements_2.len());
        for ((scalar, point), (scalar_2, point_2)) in statements.into_iter().zip(statements_2) {
          assert!(bool::from(!scalar.is_zero()));
          assert!(bool::from(!scalar_2.is_zero()));
          assert_eq!(point, point_2);
        }
      }

      // Changing any value should void the multiexp
      {
        for i in 0 .. coefficients.len() {
          let mut coefficients = coefficients.clone();
          coefficients[i] =
            <<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::G::random(&mut OsRng);
          assert!(bool::from(
            !multiexp_vartime(&verifiable_encryption_statements::<
              <Ed25519 as Curves>::ToweringCurve,
            >(
              &mut OsRng,
              &coefficients,
              &encryption_key_commitments,
              &encrypted_secret_shares
            ))
            .is_identity()
          ));
        }
        for i in 0 .. encryption_key_commitments.len() {
          let mut encryption_key_commitments = encryption_key_commitments.clone();
          encryption_key_commitments[i] =
            <<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::G::random(&mut OsRng);
          assert!(bool::from(
            !multiexp_vartime(&verifiable_encryption_statements::<
              <Ed25519 as Curves>::ToweringCurve,
            >(
              &mut OsRng,
              &coefficients,
              &encryption_key_commitments,
              &encrypted_secret_shares
            ))
            .is_identity()
          ));
        }
        for i in encrypted_secret_shares.keys() {
          let mut encrypted_secret_shares = encrypted_secret_shares.clone();
          assert!(
            encrypted_secret_shares
              .insert(
                *i,
                <<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::F::random(&mut OsRng),
              )
              .is_some()
          );
          assert!(bool::from(
            !multiexp_vartime(&verifiable_encryption_statements::<
              <Ed25519 as Curves>::ToweringCurve,
            >(
              &mut OsRng,
              &coefficients,
              &encryption_key_commitments,
              &encrypted_secret_shares
            ))
            .is_identity()
          ));
        }
      }
    }
  }
}

#[test]
fn decrypt_encrypted_share() {
  use rand_core::OsRng;
  for _ in 0 .. 128 {
    let recipient =
      Zeroizing::new(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));
    let message = <<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::F::random(&mut OsRng);

    let encrypted = {
      let ecdh_a = <<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng);
      let ecdh_b = <<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng);
      let ecdh_commitments = [
        <<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator() * ecdh_a,
        <<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator() * ecdh_b,
      ];
      let mask = {
        let recipient_pub_key =
          <<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator() * *recipient;
        let ecdh_a = recipient_pub_key * ecdh_a;
        let ecdh_b = recipient_pub_key * ecdh_b;
        <<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::G::to_xy(ecdh_a).unwrap().0 +
          (k_prime::<Ed25519>(&recipient_pub_key) *
            <<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::G::to_xy(ecdh_b).unwrap().0)
      };
      let ciphertext = mask + message;
      EncryptedSecretShare::<Ed25519> { ecdh_commitments, encrypted_secret_share: ciphertext }
    };

    assert_eq!(*encrypted.decrypt(&recipient), message);
  }
}

#[test]
fn shares_verify() {
  use rand_core::OsRng;

  let threshold = 3;
  let participants = 4;
  let generators = Generators::<Ed25519>::new(threshold, participants);

  let mut context = [0; 32];
  OsRng.fill_bytes(&mut context);

  let mut priv_keys = vec![];
  let mut pub_keys = vec![];
  for i in 0 .. participants {
    let priv_key =
      Zeroizing::new(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::F::random(&mut OsRng));
    pub_keys.push(<<Ed25519 as Curves>::EmbeddedCurve as WrappedGroup>::generator() * *priv_key);
    priv_keys.push((Participant::new(1 + i).unwrap(), priv_key));
  }

  // `verify` should work even if there's no values
  {
    let Verified { verification_shares, encrypted_secret_shares } = verify(
      &mut OsRng,
      &generators,
      threshold,
      participants,
      &pub_keys,
      &mut HashMap::new(),
      &mut HashSet::new(),
    )
    .unwrap();
    assert!(verification_shares.is_empty());
    assert!(encrypted_secret_shares.is_empty());
  }

  let mut participations = HashMap::new();
  for priv_key in &priv_keys[.. 2] {
    let participation = Dkg::<Ed25519>::participate(
      &mut OsRng,
      &generators,
      context,
      threshold,
      &pub_keys,
      &priv_key.1,
    )
    .unwrap();
    assert!(participations.insert(priv_key.0, participation).is_none());
  }

  let mut potentially_valid = HashMap::new();
  let mut faulty = HashSet::new();
  let verifier = Dkg::<Ed25519>::queue_for_batch_verification(
    &mut OsRng,
    &generators,
    context,
    threshold,
    pub_keys.len().try_into().unwrap(),
    &pub_keys,
    &participations,
    &mut potentially_valid,
    &mut faulty,
  );
  assert_eq!(potentially_valid.len(), 2);
  assert!(potentially_valid.contains_key(&priv_keys[0].0));
  assert!(potentially_valid.contains_key(&priv_keys[1].0));
  assert!(faulty.is_empty());
  {
    let generalized_bulletproofs::BatchVerifier { g, h, g_bold, h_bold, h_sum, additional } =
      &verifier;
    assert!(bool::from(!g.is_zero()));
    assert!(bool::from(!h.is_zero()));
    assert!(!g_bold.is_empty());
    assert!(!h_bold.is_empty());
    assert!(!h_sum.is_empty());
    assert!(!additional.is_empty());
  }

  Dkg::<Ed25519>::verify_structurally_valid_proofs(
    &mut OsRng,
    &generators,
    context,
    threshold,
    pub_keys.len().try_into().unwrap(),
    &pub_keys,
    &participations,
    &mut potentially_valid,
    &mut faulty,
    verifier,
  );
  assert_eq!(potentially_valid.len(), 2);
  assert!(potentially_valid.contains_key(&priv_keys[0].0));
  assert!(potentially_valid.contains_key(&priv_keys[1].0));
  assert!(faulty.is_empty());

  // Tweak a share to be invalid
  {
    let share =
      potentially_valid.get_mut(&priv_keys[0].0).unwrap().0.get_mut(&priv_keys[0].0).unwrap();
    *share += <<Ed25519 as Curves>::ToweringCurve as WrappedGroup>::F::ONE;
  }
  let result = verify(
    &mut OsRng,
    &generators,
    threshold,
    participants,
    &pub_keys,
    &mut potentially_valid,
    &mut faulty,
  );
  assert!(result.is_none());
  assert_eq!(potentially_valid.len(), 1);
  assert!(potentially_valid.contains_key(&priv_keys[1].0));
  assert_eq!(faulty, HashSet::from([priv_keys[0].0]));
}
