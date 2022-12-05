mod chain_spec;
mod service;

mod command_helper;
mod command;

mod rpc;
mod cli;
mod kafka;

fn main() -> sc_cli::Result<()> {
  command::run()
}
