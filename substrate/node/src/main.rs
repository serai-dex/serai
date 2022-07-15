mod chain_spec;
#[macro_use]
mod service;

mod command_helper;
mod command;

mod rpc;
mod cli;

fn main() -> sc_cli::Result<()> {
  command::run()
}
