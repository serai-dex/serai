# Serai Emissions Pallet

This pallet corresponds to the
["Emissions" subsections of the Economics specification](/spec/Economics.md).

### Integration Details

This will call [`serai_dex_pallet::Pallet::take_burnt_fees`] and assumes itself
to be the sole entity to do so. It does so within an
[`frame_support::traits::PreInherents`] hool which the caller _MUST_ ensure is
part of [`serai_core_pallet::Config::PreInherents`].

### Audit Status

This was
[audited by Security Research Labs](/audits/substrate/Security%20Research%20Labs%20April%202026)
as of commit `85b9d79641d603cb9a94eac8fd667ca26513a59b`. Any following changes
were not audited unless otherwise stated. Please read the linked report for
more information.
