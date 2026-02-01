# Serai Signals Pallet

Signals are how validators of the Serai network express intent. Specifically,
two functionalities are exposed:

- The ability to retire the Serai network, simultaneously signaling in favor of
  a new protocol
- The ability to permanently halt an external network for the lifetime of the
  protocol

In order for a network to be considered in favor of a signal, the required
percentage of the network's validators' key shares (or weight in the consensus
process, in the case of Serai) must be considered in favor. In order for Serai
as a whole to express a signal, the required percentage of _all_ networks (by
allocated stake) must be in favor. To retire the protocol, 80% is required. To
halt an external network, 34% is required, respecting the bounds on Byzantine
Fault Tolerance.

Once the Serai protocol expresses it will be retired, an end time will be set
four weeks into the future. After this point in time, no new blocks will be
accepted onto the network. While Serai nodes may continue to run as-is, with
all present blockchain data, they will not continue the blockchain per the
rules programmed into them when they were spawned.

The individuals running nodes can be presumed to still have interest in
continuing the blockchain. To do so, they may download an alternative node with
distinct consensus rules, including the removal of the rule which prevents
building on top of the existing blockchain. When the network was retired, such
a rule set should have been signaled in favor of. Individuals are not required
to adopt this rule set however, and may run any software of their choice to
enter into any social covenants of their choosing. The only decision expressed
here was to retire the existing consensus rules, as allowed by and encoded into
the protocol from the start.

With this in mind, the on-chain upgrade functionality frequently seen with
projects built with Substrate is not present within Serai. There is no
individual, council, or even decentralized entity which can unilaterally change
the Serai protocol's definition. All nodes will always run with the rules
programmed into them, any changes only by the individual running the node
replacing the node software themselves. This is to ensure the network's
decentralization, and with it, its security.

### Signal Lifetime

A signal to halt a network is implicitly and always considered alive.
Retirement signals live until the end of the latest-decided Serai session.
Expressed favor for a signal to halt an external network also expires after the
end of the latest-decided Serai session however, preventing historic favor
which may have been forgotten about being used to carry a vote to halt an
external network in the future.

Regarding expired retirement signals and favors, ideally nodes would be able to
run a cleanup task per their availability. Unfortunately, as Substrate commits
to the state, any/all database operations must be perfectly synchronized. While
[`Hooks::on_idle`] could be used to perform a bounded cleanup, this would
require canonicalizing a set of weights to determine how many entries may be
tidied, and would require defining a per-block limit on the amount of entries
allowed to be cleaned up. As Serai inherently risks unbounded state growth via
accounts in the coins pallet (which do not have lifetimes), the complexity of
attempting to prune expired values is omitted from this pallet.

### Implementation Details

With each favoring of a signal, the favor within a network is tallied from
scratch, enacting a computational cost linear to the amount of validators for a
network (which is bounded to a constant). Then, if the network is in favor is
recorded, and if so, the list of networks' recorded values is iterated over.
This causes a total of `v + n` operations to occur, where `v` is the amount of
validators within a network and `n` is the amount of networks, instead of
`v * n` (if every validator for every network was re-tallied).

Halting a network solely marks it as halted within the pallet. A consumer must
then use this information to prevent further actions from occurring.
