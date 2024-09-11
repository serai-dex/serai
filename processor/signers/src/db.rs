use serai_validator_sets_primitives::{Session, Slash};

use serai_db::{Get, DbTxn, create_db, db_channel};

use messages::sign::{ProcessorMessage, CoordinatorMessage};

create_db! {
  SignersGlobal {
    RegisteredKeys: () -> Vec<Session>,
    SerializedKeys: (session: Session) -> Vec<u8>,
    LatestRetiredSession: () -> Session,
    ToCleanup: () -> Vec<(Session, Vec<u8>)>,

    ToCosign: (session: Session) -> (u64, [u8; 32]),
  }
}

db_channel! {
  SignersGlobal {
    Cosign: (session: Session) -> ((u64, [u8; 32]), Vec<u8>),

    SlashReport: (session: Session) -> Vec<Slash>,
    SlashReportSignature: (session: Session) -> Vec<u8>,

    /*
      TODO: Most of these are pointless? We drop all active signing sessions on reboot. It's
      accordingly not valuable to use a DB-backed channel to communicate messages for signing
      sessions (Preprocess/Shares).

      Transactions, Batches, Slash Reports, and Cosigns all have their own mechanisms/DB entries
      and don't use the following channels. The only questions are:

      1) If it's safe to drop Reattempt? Or if we need tweaks to enable that
      2) If we reboot with a pending Reattempt, we'll participate on reboot. If we drop that
         Reattempt, we won't. Accordingly, we have degraded performance in that edge case in
         exchange for less disk IO in the majority of cases. Is that work it?
    */
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
