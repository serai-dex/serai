use frost::{Curve, MultisigKeys};

use crate::Coin;

struct Wallet<C: Coin> {
  keys: MultisigKeys<C::Curve>,
  outputs: Vec<C::Output>
}

impl<C: Coin> Wallet<C> {
  fn new(keys: &MultisigKeys<C::Curve>) -> Wallet<C> {
    Wallet {
      keys: keys.offset(
        C::Curve::hash_to_F(
          // Use distinct keys on each network by applying an additive offset
          // While it would be fine to just C::id(), including the group key creates distinct
          // offsets instead of static offsets. Under a statically offset system, a BTC key could
          // have X subtracted to find the potential group key, and then have Y added to find the
          // potential BCH group key. While this shouldn't be an issue, as this isn't a private
          // system, there are potentially other benefits to binding this to a specific group key
          &[b"Serai Processor Wallet", C::id(), &C::Curve::G_to_bytes(&keys.group_key())].concat()
        )
      ),

      outputs: vec![]
    }
  }

  async fn poll() { todo!() }
}
