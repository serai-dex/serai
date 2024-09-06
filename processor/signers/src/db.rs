use serai_validator_sets_primitives::Session;

use serai_db::{Get, DbTxn, create_db, db_channel};

use messages::sign::{ProcessorMessage, CoordinatorMessage};

db_channel! {
  SignersGlobal {
    // CompletedEventualities needs to be handled by each signer, meaning we need to turn its
    // effective spsc into a spmc. We do this by duplicating its message for all keys we're
    // signing for.
    // TODO: Populate from CompletedEventualities
    CompletedEventualitiesForEachKey: (session: Session) -> [u8; 32],

    CoordinatorToTransactionSignerMessages: (session: Session) -> CoordinatorMessage,
    TransactionSignerToCoordinatorMessages: (session: Session) -> ProcessorMessage,

    CoordinatorToBatchSignerMessages: (session: Session) -> CoordinatorMessage,
    BatchSignerToCoordinatorMessages: (session: Session) -> ProcessorMessage,

    CoordinatorToSlashReportSignerMessages: (session: Session) -> CoordinatorMessage,
    SlashReportSignerToCoordinatorMessages: (session: Session) -> ProcessorMessage,

    CoordinatorToCosignerMessages: (session: Session) -> CoordinatorMessage,
    CosignerToCoordinatorMessages: (session: Session) -> ProcessorMessage,
  }
}
