# Serai Coordinator libp2p P2P

A libp2p-backed P2P instantiation for Serai's coordinator.

The libp2p swarm is limited to validators from the Serai network. The swarm
does not maintain any of its own peer finding/routing infrastructure, instead
relying on the Serai network's connection information to dial peers. This does
limit the listening peers to only the peers immediately reachable via the same
IP address (despite the two distinct services), not hidden behind a NAT, yet is
also quite simple and gives full control of who to connect to to us.

Peers are decided via the internal `DialTask` which aims to maintain a target
amount of peers for each external network. This ensures cosigns are able to
propagate across the external networks which sign them.
