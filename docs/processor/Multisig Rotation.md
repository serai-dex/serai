# Multisig Rotation

Substrate is expected to determine when a new validator set instance will be
created, and with it, a new multisig. Upon the successful creation of a new
multisig, as determined by the multisig setting their key pair on Substrate,
rotation begins.

### Timeline

The following timeline is established:

1) The new multisig is created. All UIs should immediately start exclusively
   using the new multisig. The existing multisig publishes `Batch`s including
   both the prior multisig and the new multisig's transactions.

2) A `Batch` is published after the new multisig is created. The `Batch`'s
   external network block is considered the first external network block after
   the new multisig was created.

3) The existing multisig continues handling `Batch`s and `Burn`s for
   `CONFIRMATIONS` blocks. Any transactions created immediately before the new
   multisig was created will need this time to become confirmed, if instantly
   mined.

4) The existing multisig continues handling `Batch`s and `Burn`s for
   `CONFIRMATIONS + 1` blocks, using the new multisig as the change address,
   effecting a transfer of most outputs. The new multisig now takes the
   responsibility of signing in response to `Burn` events.

   This secondary window is intended to allow transactions which aren't instantly
   mined to still be processed.

6) Any self-outputs received outside of the prior window are immediately
   forwarded to the new multisig.

7) For a period of 6 hours, the existing multisig remains valid to receive
   outputs. Any outputs received are immediately fowarded to the new multisig,
   if a refund address can be properly forwarded (which may not be possible due
   to size limitations), or refunded immediately.

8) Once the 6 hour period has expired, and all self-outputs have been forwarded,
   the existing multisig publishes a final `Batch` inclusive of its final
   transaction. Then, it reports it has closed. No further actions by it, nor
   its validators, are expected (unless those validators remain present in the
   new multisig).

9) The new multisig confirms all transactions from the prior multisig were made
   as expected, including the reported `Batch`s.

10) The new multisig reports a successful close of the prior multisig, and
   becomes the sole multisig with full responsibilities.

### Latency and Fees

After the new multisig publishes its keys, two windows of lengths
`CONFIRMATIONS` and `CONFIRMATIONS + 1` exist to handle mempool latency and
confirmation latency. During the second window, the new multisig starts
receiving change. While that change won't be available to spend for
`CONFIRMATIONS` block, meaning there'd be no interruption to service as any
window of length `CONFIRMATIONS` will close before the interruption occurs, the
second window is of length `CONFIRMATIONS + 1`. This creates a single block
where available inputs belong to the new multisig, despite potentially being
needed by the old multisig for it to fulfill `Burn`s. On the next block,
responsibility will transfer and the `Burn`s will be handled, making this an
acceptable amount of latency.

If any self-outputs don't become spendable within the `CONFIRMATIONS + 1`
window, despite the fact they should, they'll be immediately forwarded upon
becoming available to minimize latency. This increases the amount of fees paid
as there's a lack of batching used to forward inputs. While these fees are
unfortunate, they're only paid in exceptional cases, and will be handled by the
protocol's fee handling.
