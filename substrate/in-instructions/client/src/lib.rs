#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use scale::Decode;

use jsonrpsee_core::client::ClientT;
use jsonrpsee_http_client::HttpClientBuilder;

use sp_inherents::{Error, InherentData, InherentIdentifier};

use in_instructions_pallet::{primitives::Updates, INHERENT_IDENTIFIER, InherentError};

pub struct InherentDataProvider;
impl InherentDataProvider {
  #[allow(clippy::new_without_default)] // This isn't planned to forever have empty arguments
  pub fn new() -> InherentDataProvider {
    InherentDataProvider
  }
}

#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
  async fn provide_inherent_data(&self, inherent_data: &mut InherentData) -> Result<(), Error> {
    let updates: Updates = (|| async {
      let client = HttpClientBuilder::default().build("http://127.0.0.1:5134")?;
      client.request("processor_coinUpdates", Vec::<u8>::new()).await
    })()
    .await
    .map_err(|e| {
      Error::Application(Box::from(format!("couldn't communicate with processor: {e}")))
    })?;
    inherent_data.put_data(INHERENT_IDENTIFIER, &updates)?;
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
