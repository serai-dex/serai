use serai_validator_sets_primitives::{Session, Slash};

use serai_db::{Get, DbTxn, create_db, db_channel};

use messages::sign::{ProcessorMessage, CoordinatorMessage};

create_db! {
  SignersGlobal {
    RegisteredKeys: () -> Vec<Session>,
    SerializedKeys: (session: Session) -> Vec<u8>,
    LatestRetiredSession: () -> Session,
    ToCleanup: () -> Vec<(Session, Vec<u8>)>,
  }
}

db_channel! {
  SignersGlobal {
    Cosign: (session: Session) -> (u64, [u8; 32]),
    SlashReport: (session: Session) -> Vec<Slash>,

    CoordinatorToCosignerMessages: (session: Session) -> CoordinatorMessage,
    CosignerToCoordinatorMessages: (session: Session) -> ProcessorMessage,

    CoordinatorToBatchSignerMessages: (session: Session) -> CoordinatorMessage,
    BatchSignerToCoordinatorMessages: (session: Session) -> ProcessorMessage,

    CoordinatorToSlashReportSignerMessages: (session: Session) -> CoordinatorMessage,
    SlashReportSignerToCoordinatorMessages: (session: Session) -> ProcessorMessage,

    CoordinatorToTransactionSignerMessages: (session: Session) -> CoordinatorMessage,
    TransactionSignerToCoordinatorMessages: (session: Session) -> ProcessorMessage,
  }
}
