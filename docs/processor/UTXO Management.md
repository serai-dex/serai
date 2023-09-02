# UTXO Management

UTXO-based chains have practical requirements for efficient operation which can
effectively be guaranteed to terminate with a safe end state. This document
attempts to detail such requirements, and the implementations in Serai resolving
them.

### Fees From Effecting Transactions Out

When `sriXYZ` is burnt, Serai is expected to create an output for `XYZ` as
instructed. The transaction containing this output will presumably have some fee
necessitating payment. Serai linearly amortizes this fee over all outputs this
transaction intends to create in response to burns.

While Serai could charge a fee in advance, either static or dynamic to views of
the fee market, it'd risk the fee being inaccurate. If it's too high, users have
paid fees they shouldn't have. If it's too low, Serai is insolvent. This is why
the actual fee is amortized, rather than an estimation being prepaid.

Serai could report a view, and when burning occurred, that view could be locked
in as the basis for transaction fees as used to fulfill the output in question.
This would require burns specify the most recent fee market view they're aware
of, signifying their agreeance, with Serai erroring is a new view is published
before the burn is included on-chain. Not only would this require more data be
published to Serai (widening data pipeline requirements), it'd prevent any
RBF-based solutions to dynamic fee markets causing transactions to get stuck.

### Output Frequency

Outputs can be created on an external network at rate
`max_outputs_per_tx / external_tick_rate`, where `external_tick_rate` is the
external's network limitations on spending outputs. While `external_tick_rate`
is generally writable as zero, due to mempool chaining, some external networks
may not allow spending outputs from transactions which have yet to be ordered.
Monero only allows spending outputs from transactions who have 10 confirmations,
for its own security.

Serai defines its own tick rate per external network, such that
`serai_tick_rate >= external_tick_rate`. This ensures that Serai never assumes
availability before actual availability. `serai_tick_rate` is also `> 0`. This
is since a zero `external_tick_rate` generally does not truly allow an infinite
output creation rate due to limitations on the amount of transactions allowed
in the mempool.

Define `output_creation_rate` as `max_outputs_per_tx / serai_tick_rate`. Under a
naive system which greedily accumulates inputs and linearly processes outputs,
this is the highest speed at which outputs which may be processed.

If the Serai blockchain enables burning sriXYZ at a rate exceeding
`output_creation_rate`, a backlog would form. This backlog could linearly grow
at a rate larger than the outputs could linearly shrink, creating an
ever-growing backlog, performing a DoS against Serai.

One solution would be to increase the fee associated with burning sriXYZ when
approaching `output_creation_rate`, making such a DoS unsustainable. This would
require the Serai blockchain be aware of each external network's
`output_creation_rate` and implement such a sliding fee. This 'solution' isn't
preferred as it still temporarily has a growing queue, and normal users would
also be affected by the increased fees.

The solution implemented into Serai is to consume all burns from the start of a
global queue which can be satisfied under currently available inputs. While the
consumed queue may have 256 items, which can't be processed within a single tick
by an external network whose `output_creation_rate` is 16, Serai can immediately
set a finite bound on execution duration.

For the above example parameters, Serai would create 16 outputs within its tick,
ignoring the necessity of a change output. These 16 outputs would _not_ create
any outputs Serai is expected to create in response to burns, yet instead create
16 "branch" outputs. One tick later, when the branch outputs are available to
spend, each would fund creating of 16 expected outputs.

For `e` expected outputs, the execution duration is just `log e` ticks _with the
base of the logarithm being `output_creation_rate`_. Since these `e` expected
outputs are consumed from the linearly-implemented global queue into their own
tree structure, execution duration cannot be extended. We can also re-consume
the entire global queue (barring input availability, see next section) after
just one tick, when the change output becomes available again.

Due to the logarithmic complexity of fulfilling burns, attacks require
exponential growth (which is infeasible to scale). This solution does not
require a sliding fee on Serai's side due to not needing to limit the on-chain
rate of burns, which means it doesn't so adversely affect normal users. While
an increased tree depth will increase the amount of transactions needed to
fulfill an output, increasing the fee amortized over the output and its
siblings, this fee scales linearly with the logarithmically scaling tree depth.
This is considered acceptable.

### Input Availability

The following section refers to spending an output, and then spending it again.
Spending it again, which is impossible under the UTXO model, refers to spending
the change output of the transaction it was spent in. The following section
also assumes any published transaction is immediately ordered on-chain, ignoring
the potential for latency from mempool to blockchain (as it is assumed to have a
negligible effect in practice).

When a burn for amount `a` is issued, the sum amount of immediately available
inputs may be `< a`. This is because despite each output being considered usable
on a tick basis, there is no global tick. Each output may or may not be
spendable at some moment, and spending it will prevent its availability for one
tick of a clock newly started.

This means all outputs will become available by simply waiting a single tick,
without spending any outputs during the waited tick. Any outputs unlocked at the
start of the tick will carry, and within the tick the rest of the outputs will
become unlocked.

This means that within a tick of operations, the full balance of Serai can be
considered unlocked and used to consume the entire global queue. While Serai
could wait for all its outputs to be available before popping from the front of
the global queue, eager execution as enough inputs become available provides
lower latency. Considering the tick may be an hour (as in the case of Bitcoin),
this is very appreciated.

If a full tick is waited for, due to the front of the global queue having a
notably large burn, then the entire global queue will be consumed as full input
availability means the ability to satisfy all potential burns in a solvent
system.

### Fees Incurred During Operations

While fees incurred when satisfying burn were covered above, with documentation
on how solvency is maintained, two other operating costs exists.

1) Input accumulation
2) Multisig rotations

Input accumulation refers to transactions which exist to merge inputs. Just as
there is a `max_outputs_per_tx`, there is a `max_inputs_per_tx`. When the amount
of inputs belonging to Serai exceeds `max_inputs_per_tx`, a TX merging them is
created. This TX incurs fees yet has no outputs mapping to burns to amortize
them over, creating an insolvency.

Please note that this merging occurs in parallel to create a logarithmic
execution, similar to how outputs are also processed in parallel.

As for multisig rotation, multisig rotation occurs when a new multisig for an
external network is created and the old multisig must transfer its inputs in
order for Serai to continue its operations. This operation also incurs fees
without having outputs immediately available to amortize over.

Serai could charge fees on received outputs, deducting from the amount of
`sriXYZ` minted in order to cover these operating fees. An overt amount would be
deducted to practically ensure solvency, forming a buffer. Once the buffer is
filled, fees would be reduced. As the buffer drains, fees would go back up.

This would keep charged fees in line with actual fees, once the buffer is
initially filled, yet requires:

1) Creating and tracking a buffer
2) Overcharging some users on fees

while still risking insolvency, if the actual fees keep increasing in a way
preventing successful estimation.

The solution Serai implements is to accrue insolvency, tracking each output with
a virtual amount (the amount it represents on Serai) and the actual amount. When
the output, or a descendant of it, is used to handle burns, the discrepancy
between the virtual amount and the amount is amortized over outputs. This
restores solvency while solely charging the actual fees, making Serai a
generally insolvent, always eventually solvent system.

There is the concern that a significant amount of outputs could be created,
which when merged as inputs, create a significant amount of fees as an
insolvency. This would then be forced onto random users, while the party who
created the insolvency would then be able to burn their own `sriXYZ` without
the notable insolvency.

To describe this attack in its optimal form, assume a sole malicious block
producer for an external network where `max_inputs_per_tx` is 16. The malicious
miner adds 256 outputs to Serai, not paying any fees as the block producer.
Serai must create 16 transactions to produce a set of 16 inputs, paying for 16
transaction fees in the process (the fees of which go to the malicious miner).

When Serai users burn `sriXYZ`, they are hit with the 16 transaction fees plus
the normally amortized fee. Then, the malicious miner burns their `sriXYZ`,
having the fee they capture be amortized over their output. In this process,
they remain net except for the 16 transaction fees they gain from other users,
which they profit.

A miner only has to have 7% of the external network's hash power to execute this
attack profitably. By only minting `sriXYZ` during their blocks, they pay no
fees. Then, _a miner_, which has a 7% chance of being themselves, collects the
16 transaction fees. Finally, they burn, with a 7% chance of collecting their
own fee, or a 93% chance of losing a single transaction fee.

16 attempts, costing 16 transaction fees if they always lose their single
transaction fee, will cause a slight edge they gain the 16 transaction fees at
least once, offsetting their costs.

To limit this attack vector, a flat fee of
`2 * (the estimation of an input-merging transaction fee) / max_inputs_per_tx`
is applied to each input. This means, assuming an inability to manipulate
Serai's fee estimations, creating 16 outputs to force a merge transaction (and
the associated fee) costs the attacker twice as much as the associated fee.

Even without the above flat fee, Serai remains solvent. With the above flat fee,
malicious miners on external networks can only steal from other users if they
can manipulate Serai's fee estimations so that the merge transaction fee used is
twice as high as the fees charged for causing a merge transaction. This is
assumed infeasible to perform at scale, yet even if demonstrated feasible, it
would not be a critical vulnerability against Serai. Solely a low/medium/high
vulnerability against the users (though one it would still be our responsibility
to rectify).
