use serai_runtime::{system, System, Runtime};

use crate::{Serai, SeraiError};

pub type SystemEvent = system::Event<Runtime>;
  
impl Serai {
  pub async fn system_events(&self, block: [u8; 32]) -> Result<Vec<SystemEvent>, SeraiError> {
    self
    .events::<System, _>(block, |event| {
      matches!(
        event,
        SystemEvent::CodeUpdated |
        SystemEvent::ExtrinsicFailed { .. } |
        SystemEvent::ExtrinsicSuccess { .. } |
        SystemEvent::KilledAccount { .. } |
        SystemEvent::NewAccount { .. } |
        SystemEvent::Remarked { .. }
      )
    }).await
  }

}
