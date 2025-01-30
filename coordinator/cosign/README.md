# Serai Cosign

The Serai blockchain is controlled by a set of validators referred to as the
Serai validators. These validators could attempt to double-spend, even if every
node on the network is a full node, via equivocating.

Posit:
  - The Serai validators control X SRI
  - The Serai validators produce block A swapping X SRI to Y XYZ
  - The Serai validators produce block B swapping X SRI to Z ABC
  - The Serai validators finalize block A and send to the validators for XYZ
  - The Serai validators finalize block B and send to the validators for ABC

This is solved via the cosigning protocol. The validators for XYZ and the
validators for ABC each sign their view of the Serai blockchain, communicating
amongst each other to ensure consistency.

The security of the cosigning protocol is not formally proven, and there are no
claims it achieves Byzantine Fault Tolerance. This protocol is meant to be
practical and make such attacks infeasible, when they could already be argued
difficult to perform.

### Definitions

- Cosign: A signature from a non-Serai validator set for a Serai block
- Cosign Commit: A collection of cosigns which achieve the necessary weight

### Methodology

Finalized blocks from the Serai network are intended to be cosigned if they
contain burn events. Only once cosigned should non-Serai validators process
them.

Cosigning occurs by a non-Serai validator set, using their threshold keys
declared on the Serai blockchain. Once 83% of non-Serai validator sets, by
weight, cosign a block, a cosign commit is formed. A cosign commit for a block
is considered to also cosign for all blocks preceding it.

### Bounds Under Asynchrony

Assuming an asynchronous environment fully controlled by the adversary, 34% of
a validator set may cause an equivocation. Control of 67% of non-Serai
validator sets, by weight, is sufficient to produce two distinct cosign commits
at the same position. This is due to the honest stake, 33%, being split across
the two candidates (67% + 16.5% = 83.5%, just over the threshold). This means
the cosigning protocol may produce multiple cosign commits if 34% of 67%, just
22.78%, of the non-Serai validator sets, is malicious. This would be in
conjunction with 34% of the Serai validator set (assumed 20% of total stake),
for a total stake requirement of 34% of 20% + 22.78% of 80% (25.024%). This is
an increase from the 6.8% required without the cosigning protocol.

### Bounds Under Synchrony

Assuming the honest stake within the non-Serai validator sets detect the
malicious stake within their set prior to assisting in producing a cosign for
their set, for which there is a multi-second window, 67% of 67% of non-Serai
validator sets is required to produce cosigns for those sets. This raises the
total stake requirement to 42.712% (past the usual 34% threshold).

### Behavior Reliant on Synchrony

If the Serai blockchain node detects an equivocation, it will stop responding
to all RPC requests and stop participating in finalizing further blocks. This
lets the node communicate the equivocating commits to other nodes (causing them
to exhibit the same behavior), yet prevents interaction with it.

If cosigns representing 17% of the non-Serai validators sets by weight are
detected for distinct blocks at the same position, the protocol halts. An
explicit latency period of seventy seconds is enacted after receiving a cosign
commit for the detection of such an equivocation. This is largely redundant
given how the Serai blockchain node will presumably have halted itself by this
time.

### Equivocation-Detection Avoidance

Malicious Serai validators could avoid detection of their equivocating if they
produced two distinct blockchains, A and B, with different keys declared for
the same non-Serai validator set. While the validators following A may detect
the cosigns for distinct blocks by validators following B, the cosigns would be
assumed invalid due to their signatures being verified against distinct keys.

This is prevented by requiring cosigns on the blocks which declare new keys,
ensuring all validators have a consistent view of the keys used within the
cosigning protocol (per the bounds of the cosigning protocol). These blocks are
exempt from the general policy of cosign commits cosigning all prior blocks,
preventing the newly declared keys (which aren't yet cosigned) from being used
to cosign themselves. These cosigns are flagged as "notable", are permanently
archived, and must be synced before a validator will move forward.

Cosigning the block which declares new keys also ensures agreement on the
preceding block which declared the new set, with an exact specification of the
participants and their weight, before it impacts the cosigning protocol.

### Denial of Service Concerns

Any historical Serai validator set may trigger a chain halt by producing an
equivocation after their retiry. This requires 67% to be malicious. 34% of the
active Serai validator set may also trigger a chain halt.

17% of non-Serai validator sets equivocating causing a halt means 5.67% of
non-Serai validator sets' stake may cause a halt (in an asynchronous
environment fully controlled by the adversary). In a synchronous environment
where the honest stake cannot be split across two candidates, 11.33% of
non-Serai validator sets' stake is required.

The more practical attack is for one to obtain 5.67% of non-Serai validator
sets' stake, under any network conditions, and simply go offline. This will
take 17% of validator sets offline with it, preventing any cosign commits
from being performed. A fallback protocol where validators individually produce
cosigns, removing the network's horizontal scalability but ensuring liveness,
prevents this, restoring the additional requirements for control of an
asynchronous network or 11.33% of non-Serai validator sets' stake.

### TODO

The Serai node no longer responding to RPC requests upon detecting any
equivocation, and the fallback protocol where validators individually produce
signatures, are not implemented at this time. The former means the detection of
equivocating cosigns is not redundant and the latter makes 5.67% of non-Serai
validator sets' stake the DoS threshold, even without control of an
asynchronous network.
