// Required to be for this entire file, which isn't an issue, as it wouldn't bind to the static
#![allow(non_upper_case_globals)]

use lazy_static::lazy_static;
use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::{scalar::Scalar as DalekScalar, edwards::EdwardsPoint as DalekPoint};

use group::{ff::Field, Group};
use dalek_ff_group::{ED25519_BASEPOINT_POINT, Scalar, EdwardsPoint};

use multiexp::multiexp as const_multiexp;




use curve25519_dalek::edwards::CompressedEdwardsY;
use dalek_ff_group::ED25519_BASEPOINT_POINT as G;
use std::cmp;
use hex_literal::hex;

fn prove_multiexp(pairs: &[(Scalar, EdwardsPoint)]) -> EdwardsPoint {
  const_multiexp(pairs) * *INV_EIGHT
}

use crate::{
  H as DALEK_H, Commitment, hash, hash_to_scalar as dalek_hash,
  ringct::{hash_to_point::raw_hash_to_point, bulletproofs::scalar_vector::*},
  serialize::write_varint,
};

// Bring things into ff/group
lazy_static! {
  static ref INV_EIGHT: Scalar = Scalar::from(8u8).invert().unwrap();
  static ref H: EdwardsPoint = EdwardsPoint(*DALEK_H);
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
  Scalar(dalek_hash(data))
}

// Components common between variants
pub(crate) const MAX_M: usize = 16;
const N: usize = 64;
const MAX_MN: usize = MAX_M * N;

struct Generators {
  G: Vec<EdwardsPoint>,
  H: Vec<EdwardsPoint>,
}

fn generators_core(prefix: &'static [u8]) -> Generators {
  let mut res = Generators { G: Vec::with_capacity(MAX_MN), H: Vec::with_capacity(MAX_MN) };
  for i in 0 .. MAX_MN {
    let i = 2 * i;

    let mut even = (*H).compress().to_bytes().to_vec();
    even.extend(prefix);
    let mut odd = even.clone();

    write_varint(&i.try_into().unwrap(), &mut even).unwrap();
    write_varint(&(i + 1).try_into().unwrap(), &mut odd).unwrap();
    res.H.push(EdwardsPoint(raw_hash_to_point(hash(&even))));
    res.G.push(EdwardsPoint(raw_hash_to_point(hash(&odd))));
  }
  res
}

// TODO: Have this take in other, multiplied by G, and do a single multiexp
fn vector_exponent(generators: &Generators, a: &ScalarVector, b: &ScalarVector) -> EdwardsPoint {
  debug_assert_eq!(a.len(), b.len());
  (a * &generators.G[.. a.len()]) + (b * &generators.H[.. b.len()])
}

fn hash_cache(cache: &mut Scalar, mash: &[[u8; 32]]) -> Scalar {
  let slice =
    &[cache.to_bytes().as_ref(), mash.iter().cloned().flatten().collect::<Vec<_>>().as_ref()]
      .concat();
  *cache = hash_to_scalar(slice);
  *cache
}

fn MN(outputs: usize) -> (usize, usize, usize) {
  let logN = 6;
  debug_assert_eq!(N, 1 << logN);

  let mut logM = 0;
  let mut M;
  while {
    M = 1 << logM;
    (M <= MAX_M) && (M < outputs)
  } {
    logM += 1;
  }

  (logM + logN, M, M * N)
}

fn bit_decompose(commitments: &[Commitment]) -> (ScalarVector, ScalarVector) {
  let (_, M, MN) = MN(commitments.len());

  let sv = commitments.iter().map(|c| Scalar::from(c.amount)).collect::<Vec<_>>();
  let mut aL = ScalarVector::new(MN);
  let mut aR = ScalarVector::new(MN);

  for j in 0 .. M {
    for i in (0 .. N).rev() {
      if (j < sv.len()) && ((sv[j][i / 8] & (1u8 << (i % 8))) != 0) {
        aL.0[(j * N) + i] = Scalar::one();
      } else {
        aR.0[(j * N) + i] = -Scalar::one();
      }
    }
  }

  (aL, aR)
}

fn hash_commitments(commitments: &[Commitment]) -> Scalar {
  let V = commitments.iter().map(|c| EdwardsPoint(c.calculate()) * *INV_EIGHT).collect::<Vec<_>>();
  hash_to_scalar(&V.iter().flat_map(|V| V.compress().to_bytes()).collect::<Vec<_>>())
}

fn alpha_rho<R: RngCore + CryptoRng>(
  rng: &mut R,
  generators: &Generators,
  aL: &ScalarVector,
  aR: &ScalarVector,
) -> (Scalar, EdwardsPoint) {
  let ar = Scalar::random(rng);
  (ar, (vector_exponent(generators, aL, aR) + (EdwardsPoint::generator() * ar)) * *INV_EIGHT)
}

fn LR_statements(
  a: &ScalarVector,
  G_i: &[EdwardsPoint],
  b: &ScalarVector,
  H_i: &[EdwardsPoint],
  cL: Scalar,
  U: EdwardsPoint,
) -> Vec<(Scalar, EdwardsPoint)> {
  let mut res = a
    .0
    .iter()
    .cloned()
    .zip(G_i.iter().cloned())
    .chain(b.0.iter().cloned().zip(H_i.iter().cloned()))
    .collect::<Vec<_>>();
  res.push((cL, U));
  res
}

lazy_static! {
  static ref TWO_N: ScalarVector = ScalarVector::powers(Scalar::from(2u8), N);
}

// Bulletproofs-specific
lazy_static! {
  static ref GENERATORS: Generators = generators_core(b"bulletproof");
  static ref ONE_N: ScalarVector = ScalarVector(vec![Scalar::one(); N]);
  static ref IP12: Scalar = inner_product(&ONE_N, &TWO_N);
}

// Bulletproofs+-specific
lazy_static! {
  static ref GENERATORS_PLUS: Generators = generators_core(b"bulletproof_plus");
  static ref TRANSCRIPT_PLUS: [u8; 32] =
    EdwardsPoint(raw_hash_to_point(hash(b"bulletproof_plus_transcript"))).compress().to_bytes();
}

// TRANSCRIPT_PLUS isn't a Scalar, so we need this alternative for the first hash
fn hash_plus(mash: &[[u8; 32]]) -> Scalar {
  let slice =
    &[&*TRANSCRIPT_PLUS as &[u8], mash.iter().cloned().flatten().collect::<Vec<_>>().as_ref()]
      .concat();
  hash_to_scalar(slice)
}

// Functions used in the verify_bp
// res = x^0+x^1+x^2 + ... + x^(pow-1)
fn vector_power_sum(x: Scalar, pow: usize) -> Scalar {
  debug_assert!(pow != 0);
  if pow == 0 {
    return Scalar::from(0u8);
  }
  if pow == 1 {
    return Scalar::one();
  }
  let mut prev = x;
  let mut res: Scalar = Scalar::from(1u8); 
  for i in 1..pow {
      //println!("index: {}",i);
      res = res+prev;
      prev = prev*x;
  }
res
}

// res = x^pow
fn pow_sca(x: Scalar, pow: usize) -> Scalar {
  if pow == 0 {
    return Scalar::from(1u8);
  }
  if pow == 1 {
    return x;
  }
  let mut res = x;
  for i in 1..pow {
      //println!("index: {}",i);
    res = res*x;
  }
res
}


#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OriginalStruct {
  pub(crate) A: DalekPoint,
  pub(crate) S: DalekPoint,
  pub(crate) T1: DalekPoint,
  pub(crate) T2: DalekPoint,
  pub(crate) taux: DalekScalar,
  pub(crate) mu: DalekScalar,
  pub(crate) L: Vec<DalekPoint>,
  pub(crate) R: Vec<DalekPoint>,
  pub(crate) a: DalekScalar,
  pub(crate) b: DalekScalar,
  pub(crate) t: DalekScalar,
}

impl OriginalStruct {
  #[must_use]
  pub fn verify<R: RngCore + CryptoRng>(&self, rng: &mut R, V: Vec<EdwardsPoint>) -> bool {

    //Verification on the vector sizes should be implemented here. It is very important to verify
    //if the sizes correspond to the expected 64 bits value that we are rangeproofing.

    assert!( self.taux.is_canonical(),"taux is not canonical");
    assert!( self.mu.is_canonical(),"mu is not canonical");
    assert!( self.a.is_canonical(),"a is not canonical");
    assert!( self.b.is_canonical(),"b is not canonical");
    assert!( self.t.is_canonical(),"t is not canonical");

    assert!( V.len()>=1, "V does not have at least one element");
    assert!( self.L.len() == self.R.len(), "R and L have different sizes");
    assert!( self.L.len() > 0, "Empty proof. L <= 0");


    let maxM = 16; //Max outputs in bulletproofs 
    let mut logM = 0;
    let mut M = 0;
    while M <= maxM && M < V.len() {M = 2<<logM;logM+=1;}
    assert!( self.L.len() == 6+logM, "Proof is not the expected size");


    M = 2usize.pow(self.L.len().try_into().unwrap())/N ;
    let logN = 6;
    let mut max_length = 0;
    let mut nV = 0;
    max_length = cmp::max(max_length,self.L.len());

    assert!( max_length < 32,"At least one proof is too large");

    let logM = max_length.clone();
    let maxMN = M*N;// 1 << max_length as usize;
    let MN = M*N;
    let proofs_size = V.len();

    nV = V.len() + 1;

    let mut cache:Scalar = hash_to_scalar(&V.iter().flat_map(|V| V.compress().to_bytes()).collect::<Vec<_>>());
    let y = hash_cache(&mut cache, &[self.A.compress().to_bytes(), self.S.compress().to_bytes()]);
    assert!( y != Scalar::zero(), "scalar y is zero");

    let z = hash_to_scalar(&y.to_bytes());
    cache = z;
    assert!( z != Scalar::zero(), "scalar z is zero");

    let x = hash_cache(&mut cache, &[z.to_bytes(), self.T1.compress().to_bytes(), self.T2.compress().to_bytes()]);
    hash_cache(&mut cache, &[z.to_bytes(), self.T1.compress().to_bytes(), self.T2.compress().to_bytes()]);
    cache = x;

    let x_ip = hash_cache(&mut cache, &[x.to_bytes(), self.taux.to_bytes(), self.mu.to_bytes(), self.t.to_bytes()]);
    assert!( x_ip != Scalar::zero(), "scalar x_ip is zero");


    let mut y0: Scalar = Scalar::from(0u8);
    let mut y1: Scalar = Scalar::from(0u8);
    let mut z1: Scalar = Scalar::from(0u8);
    let mut z3: Scalar = Scalar::from(0u8);
    let mut z4 = vec![Scalar::from(0u8); maxMN];
    let mut z5 = vec![Scalar::from(0u8); maxMN];

    let weight_y = Scalar::random(&mut *rng);
    let weight_z = Scalar::random(&mut *rng);

    y0 +=  -Scalar(self.taux)*weight_y;

    let zpow = ScalarVector::powers(z,M+3);
    let ip1y: Scalar = vector_power_sum(y,M*N);

    let mut k:Scalar = -(z*z*ip1y);

    let ip12: Scalar = inner_product(&ONE_N, &TWO_N);
    for j in 1..(M+1) {
        k = k - zpow[j+2] * ip12;
        }

    y1 += (Scalar(self.t)-(z*ip1y+k))*weight_y;

    let mut rounds:i32 = self.L.len() as i32;

    let mut w = Vec::<Scalar>::with_capacity(rounds as usize);
    let mut w_inv = Vec::<Scalar>::with_capacity(rounds as usize);
    let mut tmp:Scalar = Scalar::from(0u8);

    for j in 0..rounds {
        cache = hash_cache(&mut cache, &[self.L[j as usize].compress().to_bytes(), self.R[j as usize].compress().to_bytes()]);
        w.push(cache);
        w_inv.push(cache.invert().unwrap());
    }
     

    let proof8_V = V.iter().map(|&x| x * Scalar::from(8u8) ).collect::<Vec<_>>();
    let proof8_L = self.L.iter().map(|&x| EdwardsPoint(x) * Scalar::from(8u8) ).collect::<Vec<_>>();
    let proof8_R = self.R.iter().map(|&x| EdwardsPoint(x) * Scalar::from(8u8) ).collect::<Vec<_>>();
    let proof8_T1 = EdwardsPoint(self.T1) * Scalar::from(8u8);
    let proof8_T2 = EdwardsPoint(self.T2) * Scalar::from(8u8);
    let proof8_A = EdwardsPoint(self.A) * Scalar::from(8u8);
    let proof8_S = EdwardsPoint(self.S) * Scalar::from(8u8);


    let mut multiexp_data_vector = Vec::with_capacity(MN);

    for j in 0..proof8_V.len() {
        let tmp = zpow[j+2]*weight_y;
        multiexp_data_vector.push((tmp, proof8_V[j]));
        }
        
    multiexp_data_vector.push((x*weight_y,proof8_T1));
    multiexp_data_vector.push((x*x*weight_y,proof8_T2));
    multiexp_data_vector.push((weight_z,proof8_A));
    multiexp_data_vector.push((x*weight_z,proof8_S));

    let y_inv = y.invert().unwrap();
    let yinvpow = ScalarVector::powers(y_inv, MN);

    for i in 0..MN {
    let mut index:i32= i as i32;
    let mut g_scalar:Scalar = Scalar(self.a);
    let mut h_scalar:Scalar = Scalar(self.b)*yinvpow[i];
    for j in (0..rounds).rev() {
        let mut J:i32 = (w.len() as i32)-(j as i32)-1i32;
        let mut base_power:i32 = 2i32.pow(j as u32);
        if index/base_power == 0 {
            g_scalar = g_scalar * w_inv[J as usize];
            h_scalar = h_scalar * w[J as usize];
        }
        else
        {
            g_scalar = g_scalar * w[J as usize];
            h_scalar = h_scalar * w_inv[J as usize];
            index -= base_power;
        }
    }

    g_scalar += z;
    h_scalar -= (z* pow_sca(y,i as usize) + pow_sca(z,2+i/N as usize) * pow_sca(Scalar::from(2u8),i%N as usize)) * pow_sca(y_inv,i as usize);


    z4[i] -= g_scalar*weight_z;
    z5[i] -= h_scalar*weight_z;
    }

    z1 += Scalar(self.mu)*weight_z;
    z3 += (Scalar(self.t)-Scalar(self.a)*Scalar(self.b))*x_ip*weight_z;

    for j in 0..proof8_L.len() {
        tmp = w[j]*w[j]*weight_z;
        multiexp_data_vector.push((tmp, proof8_L[j]));
        tmp = w_inv[j]*w_inv[j]*weight_z;
        multiexp_data_vector.push((tmp, proof8_R[j]));
        }

    multiexp_data_vector.push((y0-z1,G));
    multiexp_data_vector.push((z3-y1,*H));

    //This is very inefficient. Send this to a table
    let mut Gi = GENERATORS.G[.. (M*N)].to_vec();
    let mut Hi = GENERATORS.H[.. (M*N)].to_vec();

    for i in 0..(M*N) {
    multiexp_data_vector.push((z4[i],Gi[i]));
    multiexp_data_vector.push((z5[i],Hi[i]));
    }

    //Checks should be sent to a list for batch proofs
    let res = const_multiexp(&multiexp_data_vector);
    println!("res = {:02X?}",res.compress().to_bytes());
    if res == EdwardsPoint::identity() { true } else { false }
}


}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlusStruct {
  pub(crate) A: DalekPoint,
  pub(crate) A1: DalekPoint,
  pub(crate) B: DalekPoint,
  pub(crate) r1: DalekScalar,
  pub(crate) s1: DalekScalar,
  pub(crate) d1: DalekScalar,
  pub(crate) L: Vec<DalekPoint>,
  pub(crate) R: Vec<DalekPoint>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Bulletproofs {
  Original(OriginalStruct),
  Plus(PlusStruct),
}

pub(crate) fn prove<R: RngCore + CryptoRng>(
  rng: &mut R,
  commitments: &[Commitment],
) -> Bulletproofs {
  let (logMN, M, MN) = MN(commitments.len());

  let (aL, aR) = bit_decompose(commitments);
  let mut cache = hash_commitments(commitments);
  let (alpha, A) = alpha_rho(&mut *rng, &GENERATORS, &aL, &aR);

  let (sL, sR) =
    ScalarVector((0 .. (MN * 2)).map(|_| Scalar::random(&mut *rng)).collect::<Vec<_>>()).split();
  let (rho, S) = alpha_rho(&mut *rng, &GENERATORS, &sL, &sR);

  let y = hash_cache(&mut cache, &[A.compress().to_bytes(), S.compress().to_bytes()]);
  let mut cache = hash_to_scalar(&y.to_bytes());
  let z = cache;

  let l0 = &aL - z;
  let l1 = sL;

  let mut zero_twos = Vec::with_capacity(MN);
  let zpow = ScalarVector::powers(z, M + 2);
  for j in 0 .. M {
    for i in 0 .. N {
      zero_twos.push(zpow[j + 2] * TWO_N[i]);
    }
  }

  let yMN = ScalarVector::powers(y, MN);
  let r0 = (&(aR + z) * &yMN) + ScalarVector(zero_twos);
  let r1 = yMN * sR;

  let t1 = inner_product(&l0, &r1) + inner_product(&l1, &r0);
  let t2 = inner_product(&l1, &r1);

  let tau1 = Scalar::random(&mut *rng);
  let tau2 = Scalar::random(rng);

  let T1 = prove_multiexp(&[(t1, *H), (tau1, EdwardsPoint::generator())]);
  let T2 = prove_multiexp(&[(t2, *H), (tau2, EdwardsPoint::generator())]);

  let x =
    hash_cache(&mut cache, &[z.to_bytes(), T1.compress().to_bytes(), T2.compress().to_bytes()]);

  let mut taux = (tau2 * (x * x)) + (tau1 * x);
  for (i, gamma) in commitments.iter().map(|c| Scalar(c.mask)).enumerate() {
    taux += zpow[i + 2] * gamma;
  }
  let mu = (x * rho) + alpha;

  let l = &l0 + &(l1 * x);
  let r = &r0 + &(r1 * x);

  let t = inner_product(&l, &r);

  let x_ip = hash_cache(&mut cache, &[x.to_bytes(), taux.to_bytes(), mu.to_bytes(), t.to_bytes()]);

  let mut a = l;
  let mut b = r;

  let yinv = y.invert().unwrap();
  let yinvpow = ScalarVector::powers(yinv, MN);

  let mut G_proof = GENERATORS.G[.. a.len()].to_vec();
  let mut H_proof = GENERATORS.H[.. a.len()].to_vec();
  H_proof.iter_mut().zip(yinvpow.0.iter()).for_each(|(this_H, yinvpow)| *this_H *= yinvpow);
  let U = *H * x_ip;

  let mut L = Vec::with_capacity(logMN);
  let mut R = Vec::with_capacity(logMN);

  while a.len() != 1 {
    let (aL, aR) = a.split();
    let (bL, bR) = b.split();

    let cL = inner_product(&aL, &bR);
    let cR = inner_product(&aR, &bL);

    let (G_L, G_R) = G_proof.split_at(aL.len());
    let (H_L, H_R) = H_proof.split_at(aL.len());

    let L_i = prove_multiexp(&LR_statements(&aL, G_R, &bR, H_L, cL, U));
    let R_i = prove_multiexp(&LR_statements(&aR, G_L, &bL, H_R, cR, U));
    L.push(L_i);
    R.push(R_i);

    let w = hash_cache(&mut cache, &[L_i.compress().to_bytes(), R_i.compress().to_bytes()]);
    let winv = w.invert().unwrap();

    a = (aL * w) + (aR * winv);
    b = (bL * winv) + (bR * w);

    if a.len() != 1 {
      G_proof = hadamard_fold(G_L, G_R, winv, w);
      H_proof = hadamard_fold(H_L, H_R, w, winv);
    }
  }

  Bulletproofs::Original(OriginalStruct {
    A: *A,
    S: *S,
    T1: *T1,
    T2: *T2,
    taux: *taux,
    mu: *mu,
    L: L.drain(..).map(|L| *L).collect(),
    R: R.drain(..).map(|R| *R).collect(),
    a: *a[0],
    b: *b[0],
    t: *t,
  })
}

pub(crate) fn prove_plus<R: RngCore + CryptoRng>(
  rng: &mut R,
  commitments: &[Commitment],
) -> Bulletproofs {
  let (logMN, M, MN) = MN(commitments.len());

  let (aL, aR) = bit_decompose(commitments);
  let mut cache = hash_plus(&[hash_commitments(commitments).to_bytes()]);
  let (mut alpha1, A) = alpha_rho(&mut *rng, &GENERATORS_PLUS, &aL, &aR);

  let y = hash_cache(&mut cache, &[A.compress().to_bytes()]);
  let mut cache = hash_to_scalar(&y.to_bytes());
  let z = cache;

  let zpow = ScalarVector::even_powers(z, 2 * M);
  // d[j*N+i] = z**(2*(j+1)) * 2**i
  let mut d = vec![Scalar::zero(); MN];
  for j in 0 .. M {
    for i in 0 .. N {
      d[(j * N) + i] = zpow[j] * TWO_N[i];
    }
  }

  let aL1 = aL - z;

  let ypow = ScalarVector::powers(y, MN + 2);
  let mut y_for_d = ScalarVector(ypow.0[1 ..= MN].to_vec());
  y_for_d.0.reverse();
  let aR1 = (aR + z) + (y_for_d * ScalarVector(d));

  for (j, gamma) in commitments.iter().map(|c| Scalar(c.mask)).enumerate() {
    alpha1 += zpow[j] * ypow[MN + 1] * gamma;
  }

  let mut a = aL1;
  let mut b = aR1;

  let yinv = y.invert().unwrap();
  let yinvpow = ScalarVector::powers(yinv, MN);

  let mut G_proof = GENERATORS_PLUS.G[.. a.len()].to_vec();
  let mut H_proof = GENERATORS_PLUS.H[.. a.len()].to_vec();

  let mut L = Vec::with_capacity(logMN);
  let mut R = Vec::with_capacity(logMN);

  while a.len() != 1 {
    let (aL, aR) = a.split();
    let (bL, bR) = b.split();

    let cL = weighted_inner_product(&aL, &bR, y);
    let cR = weighted_inner_product(&(&aR * ypow[aR.len()]), &bL, y);

    let (dL, dR) = (Scalar::random(&mut *rng), Scalar::random(&mut *rng));

    let (G_L, G_R) = G_proof.split_at(aL.len());
    let (H_L, H_R) = H_proof.split_at(aL.len());

    let mut L_i = LR_statements(&(&aL * yinvpow[aL.len()]), G_R, &bR, H_L, cL, *H);
    L_i.push((dL, ED25519_BASEPOINT_POINT));
    let L_i = prove_multiexp(&L_i);
    L.push(L_i);

    let mut R_i = LR_statements(&(&aR * ypow[aR.len()]), G_L, &bL, H_R, cR, *H);
    R_i.push((dR, ED25519_BASEPOINT_POINT));
    let R_i = prove_multiexp(&R_i);
    R.push(R_i);

    let w = hash_cache(&mut cache, &[L_i.compress().to_bytes(), R_i.compress().to_bytes()]);
    let winv = w.invert().unwrap();

    G_proof = hadamard_fold(G_L, G_R, winv, w * yinvpow[aL.len()]);
    H_proof = hadamard_fold(H_L, H_R, w, winv);

    a = (&aL * w) + (aR * (winv * ypow[aL.len()]));
    b = (bL * winv) + (bR * w);

    alpha1 += (dL * (w * w)) + (dR * (winv * winv));
  }

  let r = Scalar::random(&mut *rng);
  let s = Scalar::random(&mut *rng);
  let d = Scalar::random(&mut *rng);
  let eta = Scalar::random(rng);

  let A1 = prove_multiexp(&[
    (r, G_proof[0]),
    (s, H_proof[0]),
    (d, ED25519_BASEPOINT_POINT),
    ((r * y * b[0]) + (s * y * a[0]), *H),
  ]);
  let B = prove_multiexp(&[(r * y * s, *H), (eta, ED25519_BASEPOINT_POINT)]);
  let e = hash_cache(&mut cache, &[A1.compress().to_bytes(), B.compress().to_bytes()]);

  let r1 = (a[0] * e) + r;
  let s1 = (b[0] * e) + s;
  let d1 = ((d * e) + eta) + (alpha1 * (e * e));

  Bulletproofs::Plus(PlusStruct {
    A: *A,
    A1: *A1,
    B: *B,
    r1: *r1,
    s1: *s1,
    d1: *d1,
    L: L.drain(..).map(|L| *L).collect(),
    R: R.drain(..).map(|R| *R).collect(),
  })
}
