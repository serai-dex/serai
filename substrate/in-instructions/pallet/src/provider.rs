use scale::Decode;

use jsonrpsee_core::client::ClientT;
use jsonrpsee_http_client::HttpClientBuilder;

use sp_inherents::{Error, InherentData, InherentIdentifier};

use crate::{INHERENT_IDENTIFIER, PendingCoins, InherentError};

pub async fn get_pending_coins() -> Option<PendingCoins> {
  let client = HttpClientBuilder::default().build("http://127.0.0.1:5134").ok()?;
  client.request("processor_coins", Vec::<u8>::new()).await.ok()?
}

pub struct InherentDataProvider(Option<PendingCoins>);
impl InherentDataProvider {
  pub async fn new() -> InherentDataProvider {
    InherentDataProvider(get_pending_coins().await)
  }
}

#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
  async fn provide_inherent_data(&self, inherent_data: &mut InherentData) -> Result<(), Error> {
    if let Some(coins) = &self.0 {
      inherent_data.put_data(INHERENT_IDENTIFIER, coins)?
    }
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
