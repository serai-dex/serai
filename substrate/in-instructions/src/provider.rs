use scale::Decode;

use sp_inherents::{Error, InherentData, InherentIdentifier};

use crate::{INHERENT_IDENTIFIER, InInstruction, PendingCoins, InherentError};

fn coin_batches() -> PendingCoins {
  let batch = (0, vec![InInstruction { destination: [0xff; 32], amount: 1, data: vec![] }]);
  let batches = vec![batch];
  let coins = vec![batches];
  coins
}

pub struct InherentDataProvider(PendingCoins);
impl InherentDataProvider {
  #[allow(clippy::new_without_default)]
  pub fn new() -> Self {
    Self(coin_batches())
  }
}

#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
  fn provide_inherent_data(
    &self,
    inherent_data: &mut InherentData,
  ) -> Result<(), sp_inherents::Error> {
    inherent_data.put_data(INHERENT_IDENTIFIER, &self.0)
  }

  async fn try_handle_error(
    &self,
    identifier: &InherentIdentifier,
    mut error: &[u8],
  ) -> Option<Result<(), sp_inherents::Error>> {
    if *identifier != INHERENT_IDENTIFIER {
      return None;
    }

    Some(Err(Error::Application(Box::from(
      <InherentError as Decode>::decode(&mut error).ok()?,
    ))))
  }
}
