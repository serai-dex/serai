# Multisig Rotation

Substrate is expected to determine when a new validator set instance will be
created, and with it, a new multisig. Upon the successful creation of a new
multisig, as determined by the new multisig setting their key pair on Substrate,
rotation begins.

### Timeline

The following timeline is established:

1) The new multisig is created, and has its keys set on Serai. Once the next
   `Batch` with a new external network block is published, its block becomes the
   "queue block". The new multisig is set to activate at the "queue block", plus
   `CONFIRMATIONS` blocks (the "activation block").

   We don't use the last `Batch`'s external network block, as that `Batch` may
   be older than `CONFIRMATIONS` blocks. Any yet-to-be-included-and-finalized
   `Batch` will be within `CONFIRMATIONS` blocks of what any processor has
   scanned however, as it'll wait for inclusion and finalization before
   continuing scanning.

2) Once the "activation block" itself has been finalized on Serai, UIs should
   start exclusively using the new multisig. If the "activation block" isn't
   finalized within `2 * CONFIRMATIONS` blocks, UIs should stop making
   transactions to any multisig on that network.

   Waiting for Serai's finalization prevents a UI from using an unfinalized
   "activation block" before a re-organization to a shorter chain. If a
   transaction to Serai was carried from the unfinalized "activation block"
   to the shorter chain, it'd no longer be after the "activation block" and
   accordingly would be ignored.

   We could not wait for Serai to finalize the block, yet instead wait for the
   block to have `CONFIRMATIONS` confirmations. This would prevent needing to
   wait for an indeterminate amount of time for Serai to finalize the
   "activation block", with the knowledge it should be finalized. Doing so would
   open UIs to eclipse attacks, where they live on an alternate chain where a
   possible "activation block" is finalized, yet Serai finalizes a distinct
   "activation block". If the alternate chain was longer than the finalized
   chain, the above issue would be reopened.

   The reason for UIs stopping under abnormal behavior is as follows. Given a
   sufficiently delayed `Batch` for the "activation block", UIs will use the old
   multisig past the point it will be deprecated. Accordingly, UIs must realize
   when `Batch`s are so delayed and continued transactions are a risk. While
   `2 * CONFIRMATIONS` is presumably well within the 6 hour period (defined
   below), that period exists for low-fee transactions at time of congestion. It
   does not exist for UIs with old state, though it can be used to compensate
   for them (reducing the tolerance for inclusion delays). `2 * CONFIRMATIONS`
   is before the 6 hour period is enacted, preserving the tolerance for
   inclusion delays, yet still should only happen under highly abnormal
   circumstances.

   In order to minimize the time it takes for "activation block" to be
   finalized, a `Batch` will always be created for it, regardless of it would
   otherwise have a `Batch` created.

3) The prior multisig continues handling `Batch`s and `Burn`s for
   `CONFIRMATIONS` blocks, plus 10 minutes, after the "activation block".

   The first `CONFIRMATIONS` blocks is due to the fact the new multisig
   shouldn't actually be sent coins during this period, making it irrelevant.
   If coins are prematurely sent to the new multisig, they're artificially
   delayed until the end of the `CONFIRMATIONS` blocks plus 10 minutes period.
   This prevents an adversary from minting Serai tokens using coins in the new
   multisig, yet then burning them to drain the prior multisig, creating a lack
   of liquidity for several blocks.

   The reason for the 10 minutes is to provide grace to honest UIs. Since UIs
   will wait until Serai confirms the "activation block" for keys before sending
   to them, which will take `CONFIRMATIONS` blocks plus some latency, UIs would
   make transactions to the prior multisig past the end of this period if it was
   `CONFIRMATIONS` alone. Since the next period is `CONFIRMATIONS` blocks, which
   is how long transactions take to confirm, transactions made past the end of
   this period would only received after the next period. After the next period,
   the prior multisig adds fees and a delay to all received funds (as it
   forwards the funds from itself to the new multisig). The 10 minutes provides
   grace for latency.

   The 10 minutes is a delay on anyone who immediately transitions to the new
   multisig, in a no latency environment, yet the delay is preferable to fees
   from forwarding. It also should be less than 10 minutes thanks to various
   latencies.

4) The prior multisig continues handling `Batch`s and `Burn`s for another
   `CONFIRMATIONS` blocks.

   This is for two reasons:

   1) Coins sent to the new multisig still need time to gain sufficient
      confirmations.
   2) All outputs belonging to the prior multisig should become available within
      `CONFIRMATIONS` blocks.

   All `Burn`s handled during this period should use the new multisig for the
   change address. This should effect a transfer of most outputs.

   With the expected transfer of most outputs, and the new multisig receiving
   new external transactions, the new multisig takes the responsibility of
   signing all unhandled and newly emitted `Burn`s.

5) For the next 6 hours, all non-`Branch` outputs received are immediately
   forwarded to the new multisig. Only external transactions to the new multisig
   are included in `Batch`s.

   The new multisig infers the `InInstruction`, and refund address, for
   forwarded `External` outputs via reading what they were for the original
   `External` output.

   Alternatively, the `InInstruction`, with refund address explicitly included,
   could be included in the forwarding transaction. This may fail if the
   `InInstruction` omitted the refund address and is too large to fit in a
   transaction with one explicitly included. On such failure, the refund would
   be immediately issued instead.

6) Once the 6 hour period has expired, the prior multisig stops handling outputs
   it didn't itself create. Any remaining `Eventuality`s are completed, and any
   available/freshly available outputs are forwarded (creating new
   `Eventuality`s which also need to successfully resolve).

   Once all the 6 hour period has expired, no `Eventuality`s remain, and all
   outputs are forwarded, the multisig publishes a final `Batch` of the first
   block which met these conditions, regardless of if it would've otherwise had
   a `Batch`. Then, it reports to Substrate has closed. No further actions by
   it, nor its validators, are expected (unless those validators remain present
   in the new multisig).

7) The new multisig confirms all transactions from all prior multisigs were made
   as expected, including the reported `Batch`s.

   Unfortunately, we cannot solely check the immediately prior multisig due to
   the ability for two sequential malicious multisigs to steal. If multisig
   `n - 2` only transfers a fraction of its coins to multisig `n - 1`, multisig
   `n - 1` can 'honestly' operate on the dishonest state it was given,
   laundering it. This would let multisig `n - 1` forward the results of its
   as-expected operations from a dishonest starting point to the new multisig,
   and multisig `n` would attest to multisig `n - 1`'s expected (and therefore
   presumed honest) operations, assuming liability. This would cause an honest
   multisig to face full liability for the invalid state, causing it to be fully
   slashed (as needed to reacquire any lost coins).

   This would appear short-circuitable if multisig `n - 1` transfers coins
   exceeding the relevant Serai tokens' supply. Serai never expects to operate
   in an over-solvent state, yet balance should trend upwards due to a flat fee
   applied to each received output (preventing a griefing attack). Any balance
   greater than the tokens' supply may have had funds skimmed off the top, yet
   they'd still guarantee the solvency of Serai without any additional fees
   passed to users. Unfortunately, due to the requirement to verify the `Batch`s
   published (as else the Serai tokens' supply may be manipulated), this cannot
   actually be achieved (at least, not without a ZK proof the published `Batch`s
   were correct).

8) The new multisig reports a successful close of the prior multisig, and
   becomes the sole multisig with full responsibilities.

### Latency and Fees

Slightly before the end of step 3, the new multisig should start receiving new
external outputs. These won't be confirmed for another `CONFIRMATIONS` blocks,
and the new multisig won't start handling `Burn`s for another `CONFIRMATIONS`
blocks plus 10 minutes. Accordingly, the new multisig should only become
responsible for `Burn`s shortly after it has taken ownership of the stream of
newly received coins.

Before it takes responsibility, it also should've been transferred all internal
outputs under the standard scheduling flow. Any delayed outputs will be
immediately forwarded, and external stragglers are only reported to Serai once
sufficiently confirmed in the new multisig. Accordingly, liquidity should avoid
fragmentation during rotation. The only latency should be on the 10 minutes
present, and on delayed outputs, which should've been immediately usable, having
to wait another `CONFIRMATIONS` blocks to be confirmed once forwarded.

Immediate forwarding does unfortunately prevent batching inputs to reduce fees.
Given immediate forwarding only applies to latent outputs, considered
exceptional, and the protocol's fee handling ensures solvency, this is accepted.
