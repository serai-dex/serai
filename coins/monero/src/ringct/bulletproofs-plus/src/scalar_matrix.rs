use zeroize::{Zeroize, ZeroizeOnDrop};

use transcript::Transcript;

use ciphersuite::{group::ff::PrimeField, Ciphersuite};

use crate::ScalarVector;

// Each vector is considered a row
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ScalarMatrix<C: Ciphersuite> {
  width: usize,
  pub(crate) data: Vec<Vec<(usize, C::F)>>,
}

impl<C: Ciphersuite> ScalarMatrix<C> {
  pub fn new(width: usize) -> Self {
    ScalarMatrix { width, data: vec![] }
  }

  // The first number from the paper's matrix size definitions, the amount of rows
  pub(crate) fn length(&self) -> usize {
    self.data.len()
  }

  // The second number, the length of each row
  pub(crate) fn width(&self) -> usize {
    self.width
  }

  pub(crate) fn push(&mut self, row: Vec<(usize, C::F)>) {
    self.data.push(row);
  }

  pub(crate) fn mul_vec(&self, vector: &ScalarVector<C>) -> ScalarVector<C> {
    assert_eq!(self.length(), vector.len());
    let mut res = ScalarVector::new(self.width());
    for (row, weight) in self.data.iter().zip(vector.0.iter()) {
      for (i, item) in row {
        res[*i] += *item * weight;
      }
    }
    assert_eq!(res.len(), self.width());
    res
  }

  pub fn transcript<T: 'static + Transcript>(&self, transcript: &mut T, label: &'static [u8]) {
    // Prevent conflicts between 2x3 and 3x2
    transcript.append_message(b"length", u32::try_from(self.length()).unwrap().to_le_bytes());
    transcript.append_message(b"width", u32::try_from(self.width()).unwrap().to_le_bytes());
    for vector in &self.data {
      transcript.append_message(b"row_width", u32::try_from(vector.len()).unwrap().to_le_bytes());
      for (i, scalar) in vector {
        transcript.append_message(b"i", u32::try_from(*i).unwrap().to_le_bytes());
        transcript.append_message(label, scalar.to_repr());
      }
    }
  }
}
