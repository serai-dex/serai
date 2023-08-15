use std::collections::HashMap;

use ciphersuite::{group::ff::Field, Ciphersuite};

use crate::{
  ScalarVector, ScalarMatrix,
  arithmetic_circuit::{
    ChallengeApplicator, ChallengeReference, CommitmentReference, ProductReference,
  },
};

/// A constraint of the form WL aL + WR aR + WO aO = WV V + c.
#[must_use]
pub struct Constraint<C: Ciphersuite> {
  pub(crate) label: &'static str,
  // Each weight (C::F) is bound to a specific ProductReference (usize) to allow post-expansion to
  // valid constraints
  pub(crate) WL: Vec<(usize, C::F)>,
  pub(crate) WR: Vec<(usize, C::F)>,
  pub(crate) WO: Vec<(usize, C::F)>,
  pub(crate) WV: Vec<(usize, C::F)>,
  // Challenges are post-decided and accordingly can't be inserted into WL/WR/WO/WV at time of
  // execution. This post-expands to weighting the specified ProductReference by the specified
  // weight, derived from the challenge.
  pub(crate) challenge_weights:
    HashMap<ProductReference, (ChallengeReference, Box<dyn ChallengeApplicator<C>>)>,

  pub(crate) c: C::F,
  // challenge_weights yet for c.
  pub(crate) c_challenge: Option<(ChallengeReference, Box<dyn ChallengeApplicator<C>>)>,
}

impl<C: Ciphersuite> Clone for Constraint<C> {
  fn clone(&self) -> Self {
    assert!(self.challenge_weights.is_empty());
    assert!(self.c_challenge.is_none());
    Self {
      label: self.label,
      WL: self.WL.clone(),
      WR: self.WR.clone(),
      WO: self.WO.clone(),
      WV: self.WV.clone(),
      challenge_weights: HashMap::new(),
      c: self.c,
      c_challenge: None,
    }
  }
}

impl<C: Ciphersuite> core::fmt::Debug for Constraint<C> {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt.debug_struct("Constraint").finish_non_exhaustive()
  }
}

impl<C: Ciphersuite> Constraint<C> {
  // Create a new Constraint with the specified label.
  pub fn new(label: &'static str) -> Self {
    Self {
      label,
      WL: vec![],
      WR: vec![],
      WO: vec![],
      WV: vec![],
      challenge_weights: HashMap::new(),
      c: C::F::ZERO,
      c_challenge: None,
    }
  }

  fn relevant_weights(&mut self, product: ProductReference) -> &mut Vec<(usize, C::F)> {
    match product {
      ProductReference::Left { .. } => &mut self.WL,
      ProductReference::Right { .. } => &mut self.WR,
      ProductReference::Output { .. } => &mut self.WO,
    }
  }

  /// Cummulatively weight the specified product by the specified weight.
  pub fn weight(&mut self, product: ProductReference, weight: C::F) -> &mut Self {
    assert!(
      !self.challenge_weights.contains_key(&product),
      "weighted product already has a challenge weight"
    );

    let weights = self.relevant_weights(product);
    let id = product.id();
    for existing in &mut *weights {
      if existing.0 == id {
        existing.1 += weight;
        return self;
      }
    }
    weights.push((id, weight));
    self
  }

  /// Weight a product by a challenge, mapped as the function specifies.
  ///
  /// Panics if the product already has a weight specified in this constraint.
  pub fn weight_with_challenge(
    &mut self,
    product: ProductReference,
    challenge: ChallengeReference,
    applicator: Box<dyn ChallengeApplicator<C>>,
  ) -> &mut Self {
    if self.relevant_weights(product).iter().any(|existing| existing.0 == product.id()) {
      panic!("product weighted by challenge already has a non-challenge weight");
    }
    assert!(self.challenge_weights.insert(product, (challenge, applicator)).is_none());
    self
  }

  /// Cummulatively weight the specified commitment by the specified weight.
  pub fn weight_commitment(&mut self, variable: CommitmentReference, weight: C::F) -> &mut Self {
    for existing in &self.WV {
      assert!(existing.0 != variable.0);
    }
    self.WV.push((variable.0, weight));
    self
  }

  /// Add a value to the `c` variable on the right-hand side of the constraint statement.
  pub fn rhs_offset(&mut self, offset: C::F) -> &mut Self {
    assert!(self.c_challenge.is_none());
    self.c += offset;
    self
  }

  /// Add an applied challenge to the `c` variable on the right-hand side of the constraint
  /// statement.
  ///
  /// Panics if the rhs offset already has a weight specified in this constraint.
  pub fn rhs_offset_with_challenge(
    &mut self,
    challenge: ChallengeReference,
    applicator: Box<dyn ChallengeApplicator<C>>,
  ) -> &mut Self {
    assert!(bool::from(self.c.is_zero()));
    assert!(self.c_challenge.is_none());
    self.c_challenge = Some((challenge, applicator));
    self
  }
}

pub(crate) struct Weights<C: Ciphersuite> {
  WL: ScalarMatrix<C>,
  WR: ScalarMatrix<C>,
  WO: ScalarMatrix<C>,
  WV: ScalarMatrix<C>,
  c: ScalarVector<C>,

  challenge_weights:
    Vec<HashMap<ProductReference, (ChallengeReference, Box<dyn ChallengeApplicator<C>>)>>,
  c_challenge: Vec<Option<(ChallengeReference, Box<dyn ChallengeApplicator<C>>)>>,
}

impl<C: Ciphersuite> Weights<C> {
  pub(crate) fn new(
    products: usize,
    commitments: usize,
    constraints: Vec<Constraint<C>>,
    post_constraints: Vec<Constraint<C>>,
  ) -> Self {
    let mut WL = ScalarMatrix::new(products);
    let mut WR = ScalarMatrix::new(products);
    let mut WO = ScalarMatrix::new(products);
    let mut WV = ScalarMatrix::new(commitments);
    let mut c = Vec::with_capacity(constraints.len() + post_constraints.len());

    let mut challenge_weights = vec![];
    let mut c_challenge = vec![];

    for constraint in constraints {
      WL.push(constraint.WL);
      WR.push(constraint.WR);
      WO.push(constraint.WO);
      WV.push(constraint.WV);
      c.push(constraint.c);

      challenge_weights.push(constraint.challenge_weights);
      c_challenge.push(constraint.c_challenge);
    }

    for constraint in post_constraints {
      WL.push(constraint.WL);
      WR.push(constraint.WR);
      WO.push(constraint.WO);
      WV.push(vec![]);
      assert!(constraint.WV.is_empty());
      assert!(constraint.challenge_weights.is_empty());
      assert!(constraint.c_challenge.is_none());
    }
    Self { WL, WR, WO, WV, c: ScalarVector(c), challenge_weights, c_challenge }
  }

  pub(crate) fn build(
    &self,
    post_values: Vec<C::F>,
    challenges: &[Vec<C::F>],
  ) -> (ScalarMatrix<C>, ScalarMatrix<C>, ScalarMatrix<C>, ScalarMatrix<C>, ScalarVector<C>) {
    let mut WL = self.WL.clone();
    let mut WR = self.WR.clone();
    let mut WO = self.WO.clone();
    let WV = self.WV.clone();
    let mut c = self.c.clone();

    // Post-constraints are defined as terms on the left-hand side expecting to be equal with the
    // now-specified values
    // We just push them to the right-hand side vector accordingly
    // Note this is only safe since:
    // 1) Post-constraints are last
    // 2) Nothing else is so positionally indexed
    for post_value in post_values {
      c.0.push(post_value);
    }
    assert_eq!(WL.length(), c.len());

    for i in 0 .. self.challenge_weights.len() {
      for (product, (challenge, applicator)) in &self.challenge_weights[i] {
        let (weights, id) = match product {
          ProductReference::Left { product: id, variable: _ } => (&mut WL.data[i], id),
          ProductReference::Right { product: id, variable: _ } => (&mut WR.data[i], id),
          ProductReference::Output { product: id, variable: _ } => (&mut WO.data[i], id),
        };
        weights.push((*id, applicator(&challenges[challenge.0])));
      }

      if let Some(c_challenge) = self.c_challenge[i].as_ref() {
        c[i] = c_challenge.1(&challenges[c_challenge.0 .0]);
      }
    }

    (WL, WR, WO, WV, c)
  }
}
