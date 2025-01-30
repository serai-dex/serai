use core::time::Duration;

use tributary_sdk::tendermint::LATENCY_TIME;

use libp2p::ping::{self, Config, Behaviour};
pub use ping::Event;

pub(crate) const INTERVAL: Duration = Duration::from_secs(30);
// LATENCY_TIME represents the maximum latency for message delivery. Sending the ping, and
// receiving the pong, each have to occur within this time bound to validate the connection. We
// enforce that, as best we can, by requiring the round-trip be within twice the allowed latency.
pub(crate) const TIMEOUT: Duration = Duration::from_millis((2 * LATENCY_TIME) as u64);

pub(crate) type Behavior = Behaviour;
pub(crate) fn new_behavior() -> Behavior {
  Behavior::new(Config::default().with_interval(INTERVAL).with_timeout(TIMEOUT))
}
