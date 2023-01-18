/// A block number from the Substrate chain, considered a canonical orderer by all instances.
pub struct CanonicalNumber(u64);
/// A block number of some arbitrary chain, later-affirmed by the Substrate chain.
pub struct ChainNumber(u64);

/// Instructions for the scanner.
pub enum Instruction<C: Ciphersuite> {
  /// Update the keys being scanned for.
  /// If no keys have been prior set, these will become the keys with no further actions.
  /// If keys have been prior set, both keys will be scanned for as detailed in the Multisig
  /// documentation. The old keys will eventually stop being scanned for, leaving just the
  /// updated-to keys.
  UpdateKeys {
    activation_number: ChainNumber,
    keys: FrostKeys<C>,
  },
}

enum ScannerEvent<C: Coin> {
// Needs to be reported to Substrate
  Block(usize, <C::Block as Block>::Id),
  // Needs to be processed/sent up to Substrate
  ExternalOutput(C::Output),

  // Given a known output set, and a known series of outbound transactions, we should be able to
  // form a completely deterministic schedule S. The issue is when S has TXs which spend prior TXs
  // in S (which is needed for our logarithmic scheduling). In order to have the descendant TX, say
  // S[1], build off S[0], we need to observe when S[0] is included on-chain.
  //
  // We cannot.
  //
  // Monero (and other privacy coins) do not expose their UTXO graphs. Even if we know how to
  // create S[0], and the actual payment info behind it, we cannot observe it on the blockchain
  // unless we participated in creating it. Locking the entire schedule, when we cannot sign for
  // the entire schedule at once, to a single signing set isn't feasible.
  //
  // While any member of the active signing set can provide data enabling other signers to
  // participate, it's several KB of data which we then have to code communication for.
  // The other option is to simply not observe S[0]. Instead, observe a TX with an identical output
  // to the one in S[0] we intended to use for S[1]. It's either from S[0], or Eve, a malicious
  // actor, has sent us a forged TX which is... equally as usable? so who cares?
  //
  // The only issue is if we have multiple outputs on-chain with identical amounts and purposes.
  // Accordingly, when the scheduler makes a plan for when a specific output is available, it
  // shouldn't write that plan. It should *push* that plan to a queue of plans to perform when
  // instances of that output occur.
  BranchOutput(C::Output),

  // Should be added to the available UTXO pool with no further action
  ChangeOutput(C::Output),
}

impl Scanner<C: Coin> {
  fn new(coin: Arc<C>) -> (InChannelForInstrs, OutChannelForOutputs) {

  }

  // An async function, to be spawned on a task, to discover and report outputs
  async fn run(self) {
    loop {
      let latest = self.coin.get_latest_block_number();
      for i in (self.latest + 1) ..= latest {
        let block = self.coin.get_block(i);
        let mut outputs = scan block for all active keys;

        emit ScannerEvent::Block(i, block.id());
        for output in outputs.drain(..) {
          match output.kind() {
            OutputType::External => emit ScannerEvent::ExternalOutput,
            OutputType::Branch => emit ScannerEvent::BranchOutput,
            OutputType::Change => emit ScannerEvent::ChangeOutput,
          }
        }
      }
      self.latest = latest;

      // TODO: Use a timeout on the future instead?
      let sleep = sleep(Duration::from_secs(1));
      futures::select! {
        self.instructions.read() => {},
        sleep => {},
      }
    }
  }
}
