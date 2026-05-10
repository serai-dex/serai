use blake2::digest::{Update, VariableOutput, core_api::RtVariableCoreWrapper};

pub struct Params {
  output_size: usize,
}
impl Default for Params {
  fn default() -> Self {
    Self { output_size: 64 }
  }
}

type Blake2b = RtVariableCoreWrapper<blake2::Blake2bVarCore>;
#[derive(Debug)]
pub struct State(Blake2b);

impl Params {
  /// Create a new [`Params`] with the default configuration.
  pub fn new() -> Self {
    Self::default()
  }
  /// Specify the length for the hash's output.
  pub fn hash_length(&mut self, output_size: usize) {
    self.output_size = output_size;
  }
  /// This may panic if the specified length for the hash's output isn't applicable.
  pub fn to_state(self) -> State {
    State(Blake2b::new(self.output_size).unwrap())
  }
}

/// A hash of length up to 64 bytes.
pub struct Hash {
  digest: [u8; 64],
  len: usize,
}
impl Hash {
  pub fn as_bytes(&self) -> &[u8] {
    &self.digest[.. self.len]
  }
}

impl Default for State {
  fn default() -> Self {
    Params::default().to_state()
  }
}
impl State {
  pub fn update(&mut self, bytes: &[u8]) {
    self.0.update(bytes)
  }
  /// This may panic if the specified length for the hash's output exceeds the size of the buffer
  /// within `Hash`.
  pub fn finalize(&self) -> Hash {
    let mut out = [0; 64];
    let len = self.0.output_size();
    self.0.clone().finalize_variable(&mut out[.. len]).unwrap();
    Hash { digest: out, len }
  }
}

#[test]
fn test_blake2b_256_and_512() {
  use blake2::{
    digest::{typenum::U32, Digest},
    Blake2b, Blake2b512,
  };

  for vector in [b"".as_slice(), b"abc"] {
    let mut state = State::default();
    state.update(vector);
    assert_eq!(Blake2b512::digest(vector).as_slice(), state.finalize().as_bytes());

    let mut params = Params::default();
    params.hash_length(32);
    let mut state = params.to_state();
    state.update(vector);
    assert_eq!(Blake2b::<U32>::digest(vector).as_slice(), state.finalize().as_bytes());
  }
}
