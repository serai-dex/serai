#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(non_snake_case)]

use zeroize::{Zeroize, ZeroizeOnDrop};

use ciphersuite::{
  group::ff::{Field, PrimeField},
  Ciphersuite,
};

use generalized_bulletproofs::{
  ScalarVector, PedersenCommitment, PedersenVectorCommitment, ProofGenerators,
  transcript::{Transcript as ProverTranscript, VerifierTranscript, Commitments},
  arithmetic_circuit_proof::{AcError, ArithmeticCircuitStatement, ArithmeticCircuitWitness},
};
pub use generalized_bulletproofs::arithmetic_circuit_proof::{Variable, LinComb};

mod gadgets;

/// A trait for the transcript, whether proving for verifying, as necessary for sampling
/// challenges.
pub trait Transcript {
  /// Sample a challenge from the transacript.
  ///
  /// It is the caller's responsibility to have properly transcripted all variables prior to
  /// sampling this challenge.
  fn challenge<F: PrimeField>(&mut self) -> F;
}
impl Transcript for ProverTranscript {
  fn challenge<F: PrimeField>(&mut self) -> F {
    self.challenge()
  }
}
impl Transcript for VerifierTranscript<'_> {
  fn challenge<F: PrimeField>(&mut self) -> F {
    self.challenge()
  }
}

/// The witness for the satisfaction of this circuit.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
struct ProverData<C: Ciphersuite> {
  aL: Vec<C::F>,
  aR: Vec<C::F>,
  C: Vec<PedersenVectorCommitment<C>>,
  V: Vec<PedersenCommitment<C>>,
}

/// A struct representing a circuit.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Circuit<C: Ciphersuite> {
  muls: usize,
  // A series of linear combinations which must evaluate to 0.
  constraints: Vec<LinComb<C::F>>,
  prover: Option<ProverData<C>>,
}

impl<C: Ciphersuite> Circuit<C> {
  /// Returns the amount of multiplications used by this circuit.
  pub fn muls(&self) -> usize {
    self.muls
  }

  /// Create an instance to prove satisfaction of a circuit with.
  // TODO: Take the transcript here
  #[allow(clippy::type_complexity)]
  pub fn prove(
    vector_commitments: Vec<PedersenVectorCommitment<C>>,
    commitments: Vec<PedersenCommitment<C>>,
  ) -> Self {
    Self {
      muls: 0,
      constraints: vec![],
      prover: Some(ProverData { aL: vec![], aR: vec![], C: vector_commitments, V: commitments }),
    }
  }

  /// Create an instance to verify a proof with.
  // TODO: Take the transcript here
  pub fn verify() -> Self {
    Self { muls: 0, constraints: vec![], prover: None }
  }

  /// Evaluate a linear combination.
  ///
  /// Yields WL aL + WR aR + WO aO + WCG CG + WCH CH + WV V + c.
  ///
  /// May panic if the linear combination references non-existent terms.
  ///
  /// Returns None if not a prover.
  pub fn eval(&self, lincomb: &LinComb<C::F>) -> Option<C::F> {
    self.prover.as_ref().map(|prover| {
      let mut res = lincomb.c();
      for (index, weight) in lincomb.WL() {
        res += prover.aL[*index] * weight;
      }
      for (index, weight) in lincomb.WR() {
        res += prover.aR[*index] * weight;
      }
      for (index, weight) in lincomb.WO() {
        res += prover.aL[*index] * prover.aR[*index] * weight;
      }
      for (WCG, C) in lincomb.WCG().iter().zip(&prover.C) {
        for (j, weight) in WCG {
          res += C.g_values[*j] * weight;
        }
      }
      for (WCH, C) in lincomb.WCH().iter().zip(&prover.C) {
        for (j, weight) in WCH {
          res += C.h_values[*j] * weight;
        }
      }
      for (index, weight) in lincomb.WV() {
        res += prover.V[*index].value * weight;
      }
      res
    })
  }

  /// Multiply two values, optionally constrained, returning the constrainable left/right/out
  /// terms.
  ///
  /// May panic if any linear combinations reference non-existent terms or if the witness isn't
  /// provided when proving/is provided when verifying.
  pub fn mul(
    &mut self,
    a: Option<LinComb<C::F>>,
    b: Option<LinComb<C::F>>,
    witness: Option<(C::F, C::F)>,
  ) -> (Variable, Variable, Variable) {
    let l = Variable::aL(self.muls);
    let r = Variable::aR(self.muls);
    let o = Variable::aO(self.muls);
    self.muls += 1;

    debug_assert_eq!(self.prover.is_some(), witness.is_some());
    if let Some(witness) = witness {
      let prover = self.prover.as_mut().unwrap();
      prover.aL.push(witness.0);
      prover.aR.push(witness.1);
    }

    if let Some(a) = a {
      self.constrain_equal_to_zero(a.term(-C::F::ONE, l));
    }
    if let Some(b) = b {
      self.constrain_equal_to_zero(b.term(-C::F::ONE, r));
    }

    (l, r, o)
  }

  /// Constrain a linear combination to be equal to 0.
  ///
  /// May panic if the linear combination references non-existent terms.
  pub fn constrain_equal_to_zero(&mut self, lincomb: LinComb<C::F>) {
    self.constraints.push(lincomb);
  }

  /// Obtain the statement for this circuit.
  ///
  /// If configured as the prover, the witness to use is also returned.
  #[allow(clippy::type_complexity)]
  pub fn statement(
    self,
    generators: ProofGenerators<'_, C>,
    commitments: Commitments<C>,
  ) -> Result<(ArithmeticCircuitStatement<'_, C>, Option<ArithmeticCircuitWitness<C>>), AcError> {
    let statement = ArithmeticCircuitStatement::new(generators, self.constraints, commitments)?;

    let witness = self
      .prover
      .map(|mut prover| {
        // We can't deconstruct the witness as it implements Drop (per ZeroizeOnDrop)
        // Accordingly, we take the values within it and move forward with those
        let mut aL = vec![];
        std::mem::swap(&mut prover.aL, &mut aL);
        let mut aR = vec![];
        std::mem::swap(&mut prover.aR, &mut aR);
        let mut C = vec![];
        std::mem::swap(&mut prover.C, &mut C);
        let mut V = vec![];
        std::mem::swap(&mut prover.V, &mut V);
        ArithmeticCircuitWitness::new(ScalarVector::from(aL), ScalarVector::from(aR), C, V)
      })
      .transpose()?;

    Ok((statement, witness))
  }
}
