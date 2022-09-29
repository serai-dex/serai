use std::{sync::Arc, time::Duration};

use sp_core::{Encode, Pair};
use sp_keyring::Sr25519Keyring;
use sp_inherents::{InherentData, InherentDataProvider};

use sp_runtime::OpaqueExtrinsic;

use sc_cli::Result;
use sc_client_api::BlockBackend;

use serai_runtime as runtime;
use runtime::SystemCall;

use crate::service::FullClient;

pub struct RemarkBuilder {
  client: Arc<FullClient>,
}

impl RemarkBuilder {
  pub fn new(client: Arc<FullClient>) -> Self {
    Self { client }
  }
}

impl frame_benchmarking_cli::ExtrinsicBuilder for RemarkBuilder {
  fn pallet(&self) -> &str {
    "system"
  }
  fn extrinsic(&self) -> &str {
    "remark"
  }

  fn build(&self, nonce: u32) -> std::result::Result<OpaqueExtrinsic, &'static str> {
    Ok(OpaqueExtrinsic::from(create_benchmark_extrinsic(
      self.client.as_ref(),
      Sr25519Keyring::Bob.pair(),
      SystemCall::remark { remark: vec![] }.into(),
      nonce,
    )))
  }
}

pub fn create_benchmark_extrinsic(
  client: &FullClient,
  sender: sp_core::sr25519::Pair,
  call: runtime::RuntimeCall,
  nonce: u32,
) -> runtime::UncheckedExtrinsic {
  let extra = (
    frame_system::CheckNonZeroSender::<runtime::Runtime>::new(),
    frame_system::CheckSpecVersion::<runtime::Runtime>::new(),
    frame_system::CheckTxVersion::<runtime::Runtime>::new(),
    frame_system::CheckGenesis::<runtime::Runtime>::new(),
    frame_system::CheckEra::<runtime::Runtime>::from(sp_runtime::generic::Era::mortal(
      u64::from(
        runtime::BlockHashCount::get().checked_next_power_of_two().map(|c| c / 2).unwrap_or(2),
      ),
      client.chain_info().best_number.into(),
    )),
    frame_system::CheckNonce::<runtime::Runtime>::from(nonce),
    frame_system::CheckWeight::<runtime::Runtime>::new(),
    pallet_transaction_payment::ChargeTransactionPayment::<runtime::Runtime>::from(0),
  );

  runtime::UncheckedExtrinsic::new_signed(
    call.clone(),
    sp_runtime::AccountId32::from(sender.public()).into(),
    runtime::Signature::Sr25519(
      runtime::SignedPayload::from_raw(
        call,
        extra.clone(),
        (
          (),
          runtime::VERSION.spec_version,
          runtime::VERSION.transaction_version,
          client.block_hash(0).ok().flatten().unwrap(),
          client.chain_info().best_hash,
          (),
          (),
          (),
        ),
      )
      .using_encoded(|e| sender.sign(e)),
    ),
    extra,
  )
}

pub fn inherent_benchmark_data() -> Result<InherentData> {
  let mut inherent_data = InherentData::new();
  sp_timestamp::InherentDataProvider::new(Duration::from_millis(0).into())
    .provide_inherent_data(&mut inherent_data)
    .map_err(|e| format!("creating inherent data: {:?}", e))?;
  Ok(inherent_data)
}
