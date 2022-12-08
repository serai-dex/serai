use std::sync::{Arc, RwLock};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
  Protocol,
  wallet::{address::MoneroAddress, Fee, SpendableOutput, SignableTransaction, TransactionError},
};

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
struct SignableTransactionBuilderInternal {
  protocol: Protocol,
  fee: Fee,

  inputs: Vec<SpendableOutput>,
  payments: Vec<(MoneroAddress, u64)>,
  change_address: Option<MoneroAddress>,
  data: Vec<Vec<u8>>,
}

impl SignableTransactionBuilderInternal {
  // Takes in the change address so users don't miss that they have to manually set one
  // If they don't, all leftover funds will become part of the fee
  fn new(protocol: Protocol, fee: Fee, change_address: Option<MoneroAddress>) -> Self {
    Self { protocol, fee, inputs: vec![], payments: vec![], change_address, data: Vec::new() }
  }

  fn add_input(&mut self, input: SpendableOutput) {
    self.inputs.push(input);
  }
  fn add_inputs(&mut self, inputs: &[SpendableOutput]) {
    self.inputs.extend(inputs.iter().cloned());
  }

  fn add_payment(&mut self, dest: MoneroAddress, amount: u64) {
    self.payments.push((dest, amount));
  }
  fn add_payments(&mut self, payments: &[(MoneroAddress, u64)]) {
    self.payments.extend(payments);
  }

  fn add_data(&mut self, data: &Vec<u8>) {
    self.data.push(data.clone());
  }
}

/// A Transaction Builder for Monero transactions.
/// All methods provided will modify self while also returning a shallow copy, enabling efficient
/// chaining with a clean API.
/// In order to fork the builder at some point, clone will still return a deep copy.
#[derive(Debug)]
pub struct SignableTransactionBuilder(Arc<RwLock<SignableTransactionBuilderInternal>>);
impl Clone for SignableTransactionBuilder {
  fn clone(&self) -> Self {
    Self(Arc::new(RwLock::new((*self.0.read().unwrap()).clone())))
  }
}

impl PartialEq for SignableTransactionBuilder {
  fn eq(&self, other: &Self) -> bool {
    *self.0.read().unwrap() == *other.0.read().unwrap()
  }
}
impl Eq for SignableTransactionBuilder {}

impl Zeroize for SignableTransactionBuilder {
  fn zeroize(&mut self) {
    self.0.write().unwrap().zeroize()
  }
}

impl SignableTransactionBuilder {
  fn shallow_copy(&self) -> Self {
    Self(self.0.clone())
  }

  pub fn new(protocol: Protocol, fee: Fee, change_address: Option<MoneroAddress>) -> Self {
    Self(Arc::new(RwLock::new(SignableTransactionBuilderInternal::new(
      protocol,
      fee,
      change_address,
    ))))
  }

  pub fn add_input(&mut self, input: SpendableOutput) -> Self {
    self.0.write().unwrap().add_input(input);
    self.shallow_copy()
  }
  pub fn add_inputs(&mut self, inputs: &[SpendableOutput]) -> Self {
    self.0.write().unwrap().add_inputs(inputs);
    self.shallow_copy()
  }

  pub fn add_payment(&mut self, dest: MoneroAddress, amount: u64) -> Self {
    self.0.write().unwrap().add_payment(dest, amount);
    self.shallow_copy()
  }
  pub fn add_payments(&mut self, payments: &[(MoneroAddress, u64)]) -> Self {
    self.0.write().unwrap().add_payments(payments);
    self.shallow_copy()
  }

  pub fn add_data(&mut self, data: &Vec<u8>) -> Result<Self, TransactionError> {
    if data.len() > 255 {
      Err(TransactionError::TooMuchData)?;
    }
    self.0.write().unwrap().add_data(data);
    Ok(self.shallow_copy())
  }

  pub fn build(self) -> Result<SignableTransaction, TransactionError> {
    let read = self.0.read().unwrap();
    SignableTransaction::new(
      read.protocol,
      read.inputs.clone(),
      read.payments.clone(),
      read.change_address,
      read.data.clone(),
      read.fee,
    )
  }
}
