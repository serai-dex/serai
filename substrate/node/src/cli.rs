use sc_cli::RunCmd;

#[derive(Debug, clap::Parser)]
pub struct Cli {
  #[clap(subcommand)]
  pub subcommand: Option<Subcommand>,

  #[clap(flatten)]
  pub run: RunCmd,
}

#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
  // Remove the entire chain
  PurgeChain(sc_cli::PurgeChainCmd),

  // Revert the chain to a previous state
  Revert(sc_cli::RevertCmd),

  // DB meta columns information
  ChainInfo(sc_cli::ChainInfoCmd),
}
