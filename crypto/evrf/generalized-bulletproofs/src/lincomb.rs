use core::ops::{Add, Sub, Mul};

use zeroize::Zeroize;

use ciphersuite::group::ff::PrimeField;

use crate::ScalarVector;

/// A reference to a variable usable within linear combinations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(non_camel_case_types)]
pub enum Variable {
  /// A variable within the left vector of vectors multiplied against each other.
  aL(usize),
  /// A variable within the right vector of vectors multiplied against each other.
  aR(usize),
  /// A variable within the output vector of the left vector multiplied by the right vector.
  aO(usize),
  /// A variable within a Pedersen vector commitment, committed to with a generator from `g` (bold).
  CG {
    /// The commitment being indexed.
    commitment: usize,
    /// The index of the variable.
    index: usize,
  },
  /// A variable within a Pedersen vector commitment, committed to with a generator from `h` (bold).
  CH {
    /// The commitment being indexed.
    commitment: usize,
    /// The index of the variable.
    index: usize,
  },
  /// A variable within a Pedersen commitment.
  V(usize),
}

// Does a NOP as there shouldn't be anything critical here
impl Zeroize for Variable {
  fn zeroize(&mut self) {}
}

/// A linear combination.
///
/// Specifically, `WL aL + WR aR + WO aO + WCG C_G + WCH C_H + WV V + c`.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
#[must_use]
pub struct LinComb<F: PrimeField> {
  pub(crate) highest_a_index: Option<usize>,
  pub(crate) highest_c_index: Option<usize>,
  pub(crate) highest_v_index: Option<usize>,

  // Sparse representation of WL/WR/WO
  pub(crate) WL: Vec<(usize, F)>,
  pub(crate) WR: Vec<(usize, F)>,
  pub(crate) WO: Vec<(usize, F)>,
  // Sparse representation once within a commitment
  pub(crate) WCG: Vec<Vec<(usize, F)>>,
  pub(crate) WCH: Vec<Vec<(usize, F)>>,
  // Sparse representation of WV
  pub(crate) WV: Vec<(usize, F)>,
  pub(crate) c: F,
}

impl<F: PrimeField> From<Variable> for LinComb<F> {
  fn from(constrainable: Variable) -> LinComb<F> {
    LinComb::empty().term(F::ONE, constrainable)
  }
}

impl<F: PrimeField> Add<&LinComb<F>> for LinComb<F> {
  type Output = Self;

  fn add(mut self, constraint: &Self) -> Self {
    self.highest_a_index = self.highest_a_index.max(constraint.highest_a_index);
    self.highest_c_index = self.highest_c_index.max(constraint.highest_c_index);
    self.highest_v_index = self.highest_v_index.max(constraint.highest_v_index);

    self.WL.extend(&constraint.WL);
    self.WR.extend(&constraint.WR);
    self.WO.extend(&constraint.WO);
    while self.WCG.len() < constraint.WCG.len() {
      self.WCG.push(vec![]);
    }
    while self.WCH.len() < constraint.WCH.len() {
      self.WCH.push(vec![]);
    }
    for (sWC, cWC) in self.WCG.iter_mut().zip(&constraint.WCG) {
      sWC.extend(cWC);
    }
    for (sWC, cWC) in self.WCH.iter_mut().zip(&constraint.WCH) {
      sWC.extend(cWC);
    }
    self.WV.extend(&constraint.WV);
    self.c += constraint.c;
    self
  }
}

impl<F: PrimeField> Sub<&LinComb<F>> for LinComb<F> {
  type Output = Self;

  fn sub(mut self, constraint: &Self) -> Self {
    self.highest_a_index = self.highest_a_index.max(constraint.highest_a_index);
    self.highest_c_index = self.highest_c_index.max(constraint.highest_c_index);
    self.highest_v_index = self.highest_v_index.max(constraint.highest_v_index);

    self.WL.extend(constraint.WL.iter().map(|(i, weight)| (*i, -*weight)));
    self.WR.extend(constraint.WR.iter().map(|(i, weight)| (*i, -*weight)));
    self.WO.extend(constraint.WO.iter().map(|(i, weight)| (*i, -*weight)));
    while self.WCG.len() < constraint.WCG.len() {
      self.WCG.push(vec![]);
    }
    while self.WCH.len() < constraint.WCH.len() {
      self.WCH.push(vec![]);
    }
    for (sWC, cWC) in self.WCG.iter_mut().zip(&constraint.WCG) {
      sWC.extend(cWC.iter().map(|(i, weight)| (*i, -*weight)));
    }
    for (sWC, cWC) in self.WCH.iter_mut().zip(&constraint.WCH) {
      sWC.extend(cWC.iter().map(|(i, weight)| (*i, -*weight)));
    }
    self.WV.extend(constraint.WV.iter().map(|(i, weight)| (*i, -*weight)));
    self.c -= constraint.c;
    self
  }
}

impl<F: PrimeField> Mul<F> for LinComb<F> {
  type Output = Self;

  fn mul(mut self, scalar: F) -> Self {
    for (_, weight) in self.WL.iter_mut() {
      *weight *= scalar;
    }
    for (_, weight) in self.WR.iter_mut() {
      *weight *= scalar;
    }
    for (_, weight) in self.WO.iter_mut() {
      *weight *= scalar;
    }
    for WC in self.WCG.iter_mut() {
      for (_, weight) in WC {
        *weight *= scalar;
      }
    }
    for WC in self.WCH.iter_mut() {
      for (_, weight) in WC {
        *weight *= scalar;
      }
    }
    for (_, weight) in self.WV.iter_mut() {
      *weight *= scalar;
    }
    self.c *= scalar;
    self
  }
}

impl<F: PrimeField> LinComb<F> {
  /// Create an empty linear combination.
  pub fn empty() -> Self {
    Self {
      highest_a_index: None,
      highest_c_index: None,
      highest_v_index: None,
      WL: vec![],
      WR: vec![],
      WO: vec![],
      WCG: vec![],
      WCH: vec![],
      WV: vec![],
      c: F::ZERO,
    }
  }

  /// Add a new instance of a term to this linear combination.
  pub fn term(mut self, scalar: F, constrainable: Variable) -> Self {
    match constrainable {
      Variable::aL(i) => {
        self.highest_a_index = self.highest_a_index.max(Some(i));
        self.WL.push((i, scalar))
      }
      Variable::aR(i) => {
        self.highest_a_index = self.highest_a_index.max(Some(i));
        self.WR.push((i, scalar))
      }
      Variable::aO(i) => {
        self.highest_a_index = self.highest_a_index.max(Some(i));
        self.WO.push((i, scalar))
      }
      Variable::CG { commitment: i, index: j } => {
        self.highest_c_index = self.highest_c_index.max(Some(i));
        self.highest_a_index = self.highest_a_index.max(Some(j));
        while self.WCG.len() <= i {
          self.WCG.push(vec![]);
        }
        self.WCG[i].push((j, scalar))
      }
      Variable::CH { commitment: i, index: j } => {
        self.highest_c_index = self.highest_c_index.max(Some(i));
        self.highest_a_index = self.highest_a_index.max(Some(j));
        while self.WCH.len() <= i {
          self.WCH.push(vec![]);
        }
        self.WCH[i].push((j, scalar))
      }
      Variable::V(i) => {
        self.highest_v_index = self.highest_v_index.max(Some(i));
        self.WV.push((i, scalar));
      }
    };
    self
  }

  /// Add to the constant c.
  pub fn constant(mut self, scalar: F) -> Self {
    self.c += scalar;
    self
  }

  /// View the current weights for aL.
  pub fn WL(&self) -> &[(usize, F)] {
    &self.WL
  }

  /// View the current weights for aR.
  pub fn WR(&self) -> &[(usize, F)] {
    &self.WR
  }

  /// View the current weights for aO.
  pub fn WO(&self) -> &[(usize, F)] {
    &self.WO
  }

  /// View the current weights for CG.
  pub fn WCG(&self) -> &[Vec<(usize, F)>] {
    &self.WCG
  }

  /// View the current weights for CH.
  pub fn WCH(&self) -> &[Vec<(usize, F)>] {
    &self.WCH
  }

  /// View the current weights for V.
  pub fn WV(&self) -> &[(usize, F)] {
    &self.WV
  }

  /// View the current constant.
  pub fn c(&self) -> F {
    self.c
  }
}

pub(crate) fn accumulate_vector<F: PrimeField>(
  accumulator: &mut ScalarVector<F>,
  values: &[(usize, F)],
  weight: F,
) {
  for (i, coeff) in values {
    accumulator[*i] += *coeff * weight;
  }
}
