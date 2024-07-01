use zeroize::{Zeroize, Zeroizing};

use monero_wallet::{
  primitives::Decoys,
  ringct::RctType,
  rpc::FeeRate,
  address::MoneroAddress,
  scan::SpendableOutput,
  send::{Change, SendError, SignableTransaction},
  extra::MAX_ARBITRARY_DATA_SIZE,
};

/// A builder for Monero transactions.
#[derive(Clone, PartialEq, Eq, Zeroize, Debug)]
pub struct SignableTransactionBuilder {
  rct_type: RctType,
  outgoing_view_key: Zeroizing<[u8; 32]>,
  inputs: Vec<(SpendableOutput, Decoys)>,
  payments: Vec<(MoneroAddress, u64)>,
  change: Change,
  data: Vec<Vec<u8>>,
  fee_rate: FeeRate,
}

impl SignableTransactionBuilder {
  pub fn new(
    rct_type: RctType,
    outgoing_view_key: Zeroizing<[u8; 32]>,
    change: Change,
    fee_rate: FeeRate,
  ) -> Self {
    Self {
      rct_type,
      outgoing_view_key,
      inputs: vec![],
      payments: vec![],
      change,
      data: vec![],
      fee_rate,
    }
  }

  pub fn add_input(&mut self, input: (SpendableOutput, Decoys)) -> &mut Self {
    self.inputs.push(input);
    self
  }
  #[allow(unused)]
  pub fn add_inputs(&mut self, inputs: &[(SpendableOutput, Decoys)]) -> &mut Self {
    self.inputs.extend(inputs.iter().cloned());
    self
  }

  pub fn add_payment(&mut self, dest: MoneroAddress, amount: u64) -> &mut Self {
    self.payments.push((dest, amount));
    self
  }
  #[allow(unused)]
  pub fn add_payments(&mut self, payments: &[(MoneroAddress, u64)]) -> &mut Self {
    self.payments.extend(payments);
    self
  }

  #[allow(unused)]
  pub fn add_data(&mut self, data: Vec<u8>) -> Result<&mut Self, SendError> {
    if data.len() > MAX_ARBITRARY_DATA_SIZE {
      Err(SendError::TooMuchData)?;
    }
    self.data.push(data);
    Ok(self)
  }

  pub fn build(self) -> Result<SignableTransaction, SendError> {
    SignableTransaction::new(
      self.rct_type,
      self.outgoing_view_key,
      self.inputs,
      self.payments,
      self.change,
      self.data,
      self.fee_rate,
    )
  }
}
