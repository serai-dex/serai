# Substrate Median

An implementation of a median algorithm within a Substrate runtime.

This implementation achieves efficient complexities, even in the worst-case
scenario, but is not actually efficient for small collections due to the
constant overhead. For more information, please read the
[documentation](
  https://docs.rs/substrate-median/latest/substrate_median/trait.Median.html
).

### Audit Status

This was
[audited by Security Research Labs](/audits/substrate/Security%20Research%20Labs%20April%202026)
as of commit `786ba87125ca9205e02bf74f29c49d0e28040a08`. Any following changes
were not audited unless otherwise stated. Please read the linked report for
more information.
