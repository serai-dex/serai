use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;

use scale::Decode;

use jsonrpsee_core::client::ClientT;
use jsonrpsee_http_client::HttpClientBuilder;

use sp_inherents::{Error, InherentData, InherentIdentifier};

use crate::{INHERENT_IDENTIFIER, PendingCoins, InherentError};

async fn get_pending_coins(res: Arc<Mutex<Option<PendingCoins>>>) -> Option<()> {
  // TODO: Make this wss and reuse a connection
  let client = HttpClientBuilder::default().build("http://127.0.0.1:5134").ok()?;
  let coins = client.request("processor_coins", None).await.ok()?;
  let _ = res.lock().unwrap().insert(coins);
  None
}

lazy_static! {
  static ref PENDING: Arc<Mutex<Option<PendingCoins>>> = {
    let pending = Arc::new(Mutex::new(None));

    let pending_clone = pending.clone();
    tokio::spawn(async move {
      loop {
        get_pending_coins(pending_clone.clone()).await;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
      }
    });

    pending
  };
}

pub struct InherentDataProvider(Arc<Mutex<Option<PendingCoins>>>);
impl InherentDataProvider {
  pub fn new() -> InherentDataProvider {
    InherentDataProvider(PENDING.clone())
  }
}

#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
  fn provide_inherent_data(&self, inherent_data: &mut InherentData) -> Result<(), Error> {
    // TODO: Ensure the Option is cleared when a block is successfully added.
    if let Some(coins) = self.0.lock().unwrap().clone() {
      inherent_data.put_data(INHERENT_IDENTIFIER, &coins)?
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
