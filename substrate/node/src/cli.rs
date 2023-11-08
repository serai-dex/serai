use sc_cli::RunCmd;

#[derive(Debug, clap::Parser)]
pub struct Cli {
  #[clap(subcommand)]
  pub subcommand: Option<Subcommand>,

  #[clap(flatten)]
  pub run: RunCmd,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
  // Key management CLI utilities
  #[clap(subcommand)]
  Key(sc_cli::KeySubcommand),

  // Build a chain specification
  BuildSpec(sc_cli::BuildSpecCmd),

  // Validate blocks
  CheckBlock(sc_cli::CheckBlockCmd),

  // Export blocks
  ExportBlocks(sc_cli::ExportBlocksCmd),

  // Export the state of a given block into a chain spec
  ExportState(sc_cli::ExportStateCmd),

  // Import blocks
  ImportBlocks(sc_cli::ImportBlocksCmd),

  // Remove the entire chain
  PurgeChain(sc_cli::PurgeChainCmd),

  // Revert the chain to a previous state
  Revert(sc_cli::RevertCmd),

  // DB meta columns information
  ChainInfo(sc_cli::ChainInfoCmd),
}
