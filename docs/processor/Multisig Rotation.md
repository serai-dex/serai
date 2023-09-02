# Multisig Rotation

Substrate is expected to determine when a new validator set instance will be
created, and with it, a new multisig. Upon the successful creation of a new
multisig, as determined by the multisig setting their key pair on Substrate,
rotation begins.

### Timeline

The following timeline is established:

1) The new multisig is created. All UIs should immediately start exclusively
   using the new multisig.

2) The existing multisig waits `CONFIRMATIONS + 1` blocks. Ideally, waiting this
   amount of time makes all existing outputs available to spend. The existing
   multisig handles as many `Burn` events as it can with its available balance,
   and signs transactions accordingly. These transactions use the new multisig
   as the change address, effecting a transfer of most outputs. The new multisig
   now takes the responsibility of signing in response to `Burn` events.

3) For a period of 6 hours, the existing multisig remains valid to receive
   outputs. During this time, the existing multisig remains responsible for
   publication of `Batch` events, representing both the existing and the new
   multisig.

4) At the end of six hours, the existing multisig rejects new external state.
   Once all outputs it created to itself are spendable, which should have
   occurred during the six hour period, they and the late received external
   outputs are forwarded to the new multisig.

5) The existing multisig publishes `Batch`s until its final transaction is
   included in a `Batch`. Then, it reports it has closed. No further actions by
   it, nor its validators, are expected (unless those validators remain present
   in the new multisig).

6) The new multisig confirms all transactions from the prior multisig were made
   as expected, including the reported `Batch`s.

7) The new multisig reports a successful close of the prior multisig, and
   becomes the sole multisig with full responsibilities.

### Latency Risks

Once the new multisig publishes its keys, the existing multisig no longer
eagerly handles `Burn`s. Instead, it waits a full tick (plus an extra block),
creating a unusual period of silence, though not one intolerable.

If for some reason, outputs do not become available within the
`CONFIRMATIONS + 1` window, the ability to handle `Burn`s may be interrupted for
6 hours (assuming the outputs do become available within 6 hours, as else
signing would have been interrupted regardless).
