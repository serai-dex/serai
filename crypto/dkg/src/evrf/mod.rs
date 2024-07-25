/*
  We implement a DKG using an eVRF, as detailed in the eVRF paper. For the eVRF itself, we do not
  use a Paillier-based construction, nor the detailed construction premised on a Bulletproof.

  For reference, the detailed construction premised on a Bulletproof involves two curves, notated
  here as `C` and `E`, where the scalar field of `C` is the field of `E`. Accordingly, Bulletproofs
  over `C` can efficiently perform group operations of points of curve `E`. Each participant has a
  private point (`P_i`) on curve `E` committed to over curve `C`. The eVRF selects a pair of
  scalars `a, b`, where the participant proves in-Bulletproof the points `A_i, B_i` are
  `a * P_i, b * P_i`. The eVRF proceeds to commit to `A_i.x + B_i.x` in a Pedersen Commitment.

  Our eVRF uses
  [Generalized Bulletproofs](
    https://repo.getmonero.org/monero-project/ccs-proposals
      /uploads/a9baa50c38c6312efc0fea5c6a188bb9/gbp.pdf
  ).
  This allows us much larger witnesses without growing the reference string, and enables us to
  efficiently sample challenges off in-circuit variables (via placing the variables in a vector
  commitment, then challenging from a transcript of the commitments). We proceed to use
  [elliptic curve divisors](
    https://repo.getmonero.org/-/project/54/
      uploads/eb1bf5b4d4855a3480c38abf895bd8e8/Veridise_Divisor_Proofs.pdf
  )
  (which require the ability to sample a challenge off in-circuit variables) to prove discrete
  logarithms efficiently.

  This is done via having a private scalar (`p_i`) on curve `E`, not a private point, and
  publishing the public key for it (`P_i = p_i * G`, where `G` is a generator of `E`). The eVRF
  samples two points with unknown discrete logarithms `A, B`, and the circuit proves a Pedersen
  Commitment commits to `(p_i * A).x + (p_i * B).x`.

  With the eVRF established, we now detail our other novel aspect. The eVRF paper expects secret
  shares to be sent to the other parties yet does not detail a precise way to do so. If we
  encrypted the secret shares with some stream cipher, each recipient would have to attest validity
  or accuse the sender of impropriety. We want an encryption scheme where anyone can verify the
  secret shares were encrypted properly, without additional info, efficiently.

  Please note from the published commitments, it's possible to calculcate a commitment to the
  secret share each party should receive (`V_i`).

  We have the sender sample two scalars per recipient, denoted `x_i, y_i` (where `i` is the
  recipient index). They perform the eVRF to prove a Pedersen Commitment commits to
  `z_i = (x_i * P_i).x + (y_i * P_i).x` and `x_i, y_i` are the discrete logarithms of `X_i, Y_i`
  over `G`. They then publish the encrypted share `s_i + z_i` and `X_i, Y_i`.

  The recipient is able to decrypt the share via calculating
  `s_i - ((p_i * X_i).x + (p_i * Y_i).x)`.

  To verify the secret share, we have the `F` terms of the Pedersen Commitments revealed (where
  `F, H` are generators of `C`, `F` is used for binding and `H` for blinding). This already needs
  to be done for the eVRF outputs used within the DKG, in order to obtain thecommitments to the
  coefficients. When we have the commitment `Z_i = ((p_i * A).x + (p_i * B).x) * F`, we simply
  check `s_i * F = Z_i + V_i`.

  In order to open the Pedersen Commitments to their `F` terms, we transcript the commitments and
  the claimed openings, then assign random weights to each pair of `(commitment, opening). The
  prover proves knowledge of the discrete logarithm of the sum weighted commitments, minus the sum
  sum weighted openings, over `H`.

  The benefit to this construction is that given an broadcast channel which is reliable and
  ordered, only `t` messages must be broadcast from honest parties in order to create a `t`-of-`n`
  multisig. If the encrypted secret shares were not verifiable, one would need at least `t + n`
  messages to ensure every participant has a correct dealing and can participate in future
  reconstructions of the secret. This would also require all `n` parties be online, whereas this is
  robust to threshold `t`.
*/

use core::ops::Deref;
use std::{
  io::{self, Read, Write},
  collections::{HashSet, HashMap},
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};

use ciphersuite::{
  group::{
    ff::{Field, PrimeField},
    Group,
  },
  Ciphersuite,
};
use multiexp::multiexp_vartime;

use generalized_bulletproofs::{Generators, arithmetic_circuit_proof::*};
use ec_divisors::DivisorCurve;

use crate::{Participant, DkgError, ThresholdParams, ThresholdCore};

pub(crate) mod proof;
pub use proof::*;

/// Participation in the DKG.
///
/// `Participation` is meant to be broadcast to all other participants over an authenticated,
/// reliable broadcast channel.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Participation<C: Ciphersuite> {
  proof: Vec<u8>,
  encrypted_secret_shares: HashMap<Participant, C::F>,
}

impl<C: Ciphersuite> Participation<C> {
  fn read<R: Read>(reader: &mut R, _params: ThresholdParams) -> io::Result<Self> {
    // TODO: Replace `len` with some calculcation deterministic to the params
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    let len = usize::try_from(u32::from_le_bytes(len)).expect("<32-bit platform?");

    // Don't allocate a buffer for the claimed length
    // Read chunks until we reach the claimed length
    // This means if we were told to read GB, we must actually be sent GB before allocating as such
    const CHUNK_SIZE: usize = 1024;
    let mut proof = Vec::with_capacity(len.min(CHUNK_SIZE));
    while proof.len() < len {
      let next_chunk = (len - proof.len()).min(CHUNK_SIZE);
      let old_proof_len = proof.len();
      proof.resize(old_proof_len + next_chunk, 0);
      reader.read_exact(&mut proof[old_proof_len ..])?;
    }

    Ok(Self { proof, encrypted_secret_shares: todo!("TODO") })
  }

  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&u32::try_from(self.proof.len()).unwrap().to_le_bytes())?;
    writer.write_all(&self.proof)?;
    // TODO: secret shares
    Ok(())
  }
}

fn polynomial<F: PrimeField + Zeroize>(
  coefficients: &[Zeroizing<F>],
  l: Participant,
) -> Zeroizing<F> {
  let l = F::from(u64::from(u16::from(l)));
  // This should never be reached since Participant is explicitly non-zero
  assert!(l != F::ZERO, "zero participant passed to polynomial");
  let mut share = Zeroizing::new(F::ZERO);
  for (idx, coefficient) in coefficients.iter().rev().enumerate() {
    *share += coefficient.deref();
    if idx != (coefficients.len() - 1) {
      *share *= l;
    }
  }
  share
}

fn share_verification_statements<C: Ciphersuite>(
  rng: &mut (impl RngCore + CryptoRng),
  commitments: &[C::G],
  n: u16,
  encryption_commitments: &[C::G],
  encrypted_secret_shares: &HashMap<Participant, C::F>,
) -> (C::F, Vec<(C::F, C::G)>) {
  debug_assert_eq!(usize::from(n), encryption_commitments.len());
  debug_assert_eq!(usize::from(n), encrypted_secret_shares.len());

  let mut g_scalar = C::F::ZERO;
  let mut pairs = Vec::with_capacity(commitments.len() + encryption_commitments.len());
  for commitment in commitments {
    pairs.push((C::F::ZERO, *commitment));
  }

  let mut weight;
  for (i, enc_share) in encrypted_secret_shares {
    let enc_commitment = encryption_commitments[usize::from(u16::from(*i)) - 1];

    weight = C::F::random(&mut *rng);

    // s_i F
    g_scalar += weight * enc_share;
    // - Z_i
    let weight = -weight;
    pairs.push((weight, enc_commitment));
    // - V_i
    {
      let i = C::F::from(u64::from(u16::from(*i)));
      // The first `commitments.len()` pairs are for the commitments
      (0 .. commitments.len()).fold(weight, |exp, j| {
        pairs[j].0 += exp;
        exp * i
      });
    }
  }

  (g_scalar, pairs)
}

/// Struct to perform/verify the DKG with.
#[derive(Debug)]
pub struct EvrfDkg<C: EvrfCurve> {
  t: u16,
  n: u16,
  evrf_public_keys: Vec<<C::EmbeddedCurve as Ciphersuite>::G>,
  participations: HashMap<Participant, (HashMap<Participant, C::F>, EvrfVerifyResult<C>)>,
}

impl<C: EvrfCurve> EvrfDkg<C>
where
  <<C as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G:
    DivisorCurve<FieldElement = <C as Ciphersuite>::F>,
{
  /// Participate in performing the DKG for the specified parameters.
  ///
  /// The context MUST be unique across invocations. Reuse of context will lead to sharing
  /// prior-shared secrets.
  pub fn participate(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C>,
    context: [u8; 32],
    t: u16,
    evrf_public_keys: &[<C::EmbeddedCurve as Ciphersuite>::G],
    evrf_private_key: &Zeroizing<<C::EmbeddedCurve as Ciphersuite>::F>,
  ) -> Result<Participation<C>, AcError> {
    if generators.g() != C::generator() {
      todo!("TODO");
    }

    let evrf_public_key = <C::EmbeddedCurve as Ciphersuite>::generator() * evrf_private_key.deref();
    let Ok(n) = u16::try_from(evrf_public_keys.len()) else {
      todo!("TODO");
    };
    if (t == 0) || (t > n) {
      todo!("TODO");
    }
    if !evrf_public_keys.iter().any(|key| *key == evrf_public_key) {
      todo!("TODO");
    };

    let EvrfProveResult { coefficients, encryption_masks, proof } =
      Evrf::prove(rng, generators, evrf_private_key, context, usize::from(t), evrf_public_keys)?;

    let mut encrypted_secret_shares = HashMap::new();
    for (l, encryption_mask) in (1 ..= n).map(Participant).zip(encryption_masks) {
      let share = polynomial::<C::F>(&coefficients, l);
      encrypted_secret_shares.insert(l, *share + *encryption_mask);
    }

    Ok(Participation { proof, encrypted_secret_shares })
  }

  /// Check if a batch of `Participation`s are valid.
  ///
  /// if any `Participation` is invalid, it will be returned in the `Err` of the result. If all
  /// `Participation`s are valid and there's at least `t`, an instance of this struct (usable to
  /// obtain a threshold share of generated key) is returned. If all are valid and there's not at
  /// least `t`, an error of an empty list is returned after validation.
  pub fn verify(
    rng: &mut (impl RngCore + CryptoRng),
    generators: &Generators<C>,
    context: [u8; 32],
    t: u16,
    evrf_public_keys: &[<C::EmbeddedCurve as Ciphersuite>::G],
    participations: &HashMap<Participant, Participation<C>>,
  ) -> Result<Self, Vec<Participant>> {
    let Ok(n) = u16::try_from(evrf_public_keys.len()) else { todo!("TODO") };
    if (t == 0) || (t > n) {
      todo!("TODO");
    }
    for i in participations.keys() {
      if u16::from(*i) > n {
        todo!("TODO");
      }
    }

    let mut res = HashMap::new();
    let mut faulty = HashSet::new();

    let mut evrf_verifier = generators.batch_verifier();
    for (i, participation) in participations {
      // Clone the verifier so if this proof is faulty, it doesn't corrupt the verifier
      let mut verifier_clone = evrf_verifier.clone();
      let Ok(data) = Evrf::<C>::verify(
        rng,
        generators,
        &mut verifier_clone,
        evrf_public_keys[usize::from(u16::from(*i)) - 1],
        context,
        usize::from(t),
        evrf_public_keys,
        &participation.proof,
      ) else {
        faulty.insert(*i);
        continue;
      };
      evrf_verifier = verifier_clone;

      res.insert(*i, (participation.encrypted_secret_shares.clone(), data));
    }
    debug_assert_eq!(res.len() + faulty.len(), participations.len());

    // Perform the batch verification of the eVRFs
    if !generators.verify(evrf_verifier) {
      // If the batch failed, verify them each individually
      for (i, participation) in participations {
        if faulty.contains(i) {
          continue;
        }
        let mut evrf_verifier = generators.batch_verifier();
        Evrf::<C>::verify(
          rng,
          generators,
          &mut evrf_verifier,
          evrf_public_keys[usize::from(u16::from(*i)) - 1],
          context,
          usize::from(t),
          evrf_public_keys,
          &participation.proof,
        )
        .expect("evrf failed basic checks yet prover wasn't prior marked faulty");
        if !generators.verify(evrf_verifier) {
          res.remove(i);
          faulty.insert(*i);
        }
      }
    }
    debug_assert_eq!(res.len() + faulty.len(), participations.len());

    // Perform the batch verification of the shares
    {
      let mut share_verification_statements_actual = HashMap::with_capacity(res.len());
      if !{
        let mut g_scalar = C::F::ZERO;
        let mut pairs = Vec::with_capacity(res.len() * (usize::from(t) + evrf_public_keys.len()));
        for (i, (encrypted_secret_shares, data)) in &res {
          let (this_g_scalar, mut these_pairs) = share_verification_statements::<C>(
            &mut *rng,
            &data.coefficients,
            evrf_public_keys
              .len()
              .try_into()
              .expect("n prior checked to be <= u16::MAX couldn't be converted to a u16"),
            &data.encryption_commitments,
            encrypted_secret_shares,
          );
          g_scalar += this_g_scalar;
          pairs.extend(&these_pairs);

          these_pairs.push((this_g_scalar, generators.g()));
          share_verification_statements_actual.insert(*i, these_pairs);
        }
        pairs.push((g_scalar, generators.g()));
        bool::from(multiexp_vartime(&pairs).is_identity())
      } {
        // If the batch failed, verify them each individually
        for (i, pairs) in share_verification_statements_actual {
          if !bool::from(multiexp_vartime(&pairs).is_identity()) {
            res.remove(&i);
            faulty.insert(i);
          }
        }
      }
    }
    debug_assert_eq!(res.len() + faulty.len(), participations.len());

    let mut faulty = faulty.into_iter().collect::<Vec<_>>();
    if !faulty.is_empty() {
      faulty.sort_unstable();
      Err(faulty)?;
    }

    if res.len() < usize::from(t) {
      Err(vec![])?;
    }

    Ok(EvrfDkg { t, n, evrf_public_keys: evrf_public_keys.to_vec(), participations: res })
  }

  pub fn keys(
    self,
    evrf_private_key: &Zeroizing<<C::EmbeddedCurve as Ciphersuite>::F>,
  ) -> Option<ThresholdCore<C>> {
    let evrf_public_key = <C::EmbeddedCurve as Ciphersuite>::generator() * evrf_private_key.deref();
    let Some(i) = self.evrf_public_keys.iter().position(|key| *key == evrf_public_key) else {
      None?
    };
    let i = u16::try_from(i).expect("n <= u16::MAX yet i > u16::MAX?");
    let i = Participant(1 + i);

    let mut secret_share = Zeroizing::new(C::F::ZERO);
    for (shares, evrf_data) in self.participations.values() {
      let mut ecdh = Zeroizing::new(C::F::ZERO);
      for point in evrf_data.ecdh_keys[usize::from(u16::from(i)) - 1] {
        // TODO: Explicitly ban 0-ECDH commitments, 0-eVRF public keys, and gen non-zero keys
        let (mut x, mut y) =
          <C::EmbeddedCurve as Ciphersuite>::G::to_xy(point * evrf_private_key.deref()).unwrap();
        *ecdh += x;
        x.zeroize();
        y.zeroize();
      }
      *secret_share += shares[&i] - ecdh.deref();
    }

    // Stripe commitments per t and sum them in advance. Calculating verification shares relies on
    // these sums so preprocessing them is a massive speedup
    let mut stripes = Vec::with_capacity(usize::from(self.t));
    for t in 0 .. usize::from(self.t) {
      stripes.push(
        self.participations.values().map(|(_, evrf_data)| evrf_data.coefficients[t]).sum::<C::G>(),
      );
    }

    // Calculate each user's verification share
    let mut verification_shares = HashMap::new();
    for j in (1 ..= self.n).map(Participant) {
      verification_shares.insert(
        j,
        if j == i {
          C::generator() * secret_share.deref()
        } else {
          fn exponential<C: Ciphersuite>(i: Participant, values: &[C::G]) -> Vec<(C::F, C::G)> {
            let i = C::F::from(u16::from(i).into());
            let mut res = Vec::with_capacity(values.len());
            (0 .. values.len()).fold(C::F::ONE, |exp, l| {
              res.push((exp, values[l]));
              exp * i
            });
            res
          }
          multiexp_vartime(&exponential::<C>(j, &stripes))
        },
      );
    }

    Some(ThresholdCore {
      params: ThresholdParams::new(self.t, self.n, i).unwrap(),
      secret_share,
      group_key: stripes[0],
      verification_shares,
    })
  }
}
