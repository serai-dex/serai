# Patches

These patches are to improve Serai's supply chain in various manners. Some
patches update to a crate's latest version (after reviewing no breaking changes
occurred) to de-duplicate our tree, some patches consolidate dependencies
around equivalents, and some are stubs to prove they aren't actually compiled
(allowing pruning our `Cargo.lock` of their sub-tree).

The reasons for each patch are included with the associated entry within
`Cargo.toml`.
