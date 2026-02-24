# Serai Emissions Pallet

This pallet corresponds to the
["Emissions" subsections of the Economics specification](/spec/Economics.md).

### Integration Details

This will call [`serai_dex_pallet::Pallet::take_burnt_fees`] and assumes itself
to be the sole entity to do so. It does so within an
[`frame_support::traits::PreInherents`] hool which the caller _MUST_ ensure is
part of [`serai_core_pallet::Config::PreInherents`].
