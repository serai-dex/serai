mod types;
pub use types::{TendermintClientMinimal, TendermintValidator};

mod validators;

pub(crate) mod tendermint;
pub use tendermint::TendermintImport;

mod block_import;
mod import_queue;
pub use import_queue::{TendermintImportQueue, import_queue};

pub(crate) mod gossip;
pub(crate) mod authority;
pub use authority::TendermintAuthority;

mod select_chain;
pub use select_chain::TendermintSelectChain;

const CONSENSUS_ID: [u8; 4] = *b"tend";
