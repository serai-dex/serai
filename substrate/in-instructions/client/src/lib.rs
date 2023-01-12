#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use scale::Decode;

use jsonrpsee_core::client::ClientT;
use jsonrpsee_http_client::HttpClientBuilder;

use sp_inherents::{Error, InherentData, InherentIdentifier};

use in_instructions_pallet::{INHERENT_IDENTIFIER, PendingCoins, InherentError};

pub struct InherentDataProvider;
impl InherentDataProvider {
  pub fn new() -> InherentDataProvider {
    InherentDataProvider
  }
}

#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
  async fn provide_inherent_data(&self, inherent_data: &mut InherentData) -> Result<(), Error> {
    let coins: PendingCoins = (|| async {
      let client = HttpClientBuilder::default().build("http://127.0.0.1:5134").ok()?;
      client.request("processor_coins", Vec::<u8>::new()).await.ok()
    })()
    .await
    .ok_or(Error::Application(Box::from("couldn't communicate with processor")))?;
    inherent_data.put_data(INHERENT_IDENTIFIER, &coins)?;
    Ok(())
  }

  async fn try_handle_error(
    &self,
    identifier: &InherentIdentifier,
    mut error: &[u8],
  ) -> Option<Result<(), Error>> {
    if *identifier != INHERENT_IDENTIFIER {
      return None;
    }

    Some(Err(Error::Application(Box::from(<InherentError as Decode>::decode(&mut error).ok()?))))
  }
}
