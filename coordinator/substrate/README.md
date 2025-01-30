# Serai Coordinator Substrate

This crate manages the Serai coordinators's interactions with Serai's Substrate blockchain.

Two event streams are defined:

- Canonical events, which must be handled by every validator, regardless of the sets they're present
  in. These are represented by `serai_processor_messages::substrate::CoordinatorMessage`.
- Ephemeral events, which only need to be handled by the validators present within the sets they
  relate to. These are represented by two channels, `NewSet` and `SignSlashReport`.

The canonical event stream is available without provision of a validator's public key. The ephemeral
event stream requires provision of a validator's public key. Both are ordered within themselves, yet
there are no ordering guarantees across the two.

Additionally, a collection of tasks are defined to publish data onto Serai:

- `SetKeysTask`, which sets the keys generated via DKGs onto Serai.
- `PublishBatchTask`, which publishes `Batch`s onto Serai.
- `PublishSlashReportTask`, which publishes `SlashReport`s onto Serai.
