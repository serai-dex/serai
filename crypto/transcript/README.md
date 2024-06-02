# Flexible Transcript

Flexible Transcript is a crate offering:
- `Transcript`, a trait offering functions transcripts should implement.
- `DigestTranscript`, a competent transcript format instantiated against a
  provided hash function.
- `MerlinTranscript`, a wrapper of `merlin` into the trait (available via the
  `merlin` feature).
- `RecommendedTranscript`, a transcript recommended for usage in applications.
  Currently, this is `DigestTranscript<Blake2b512>` (available via the
  `recommended` feature).

The trait was created while working on an IETF draft which defined an incredibly
simple transcript format. Extensions of the protocol would quickly require a
more competent format, yet implementing the one specified was mandatory to meet
the specification. Accordingly, the library implementing the draft defined an
`IetfTranscript`, dropping labels and not allowing successive challenges, yet
thanks to the trait, allowed protocols building on top to provide their own
transcript format as needed.

`DigestTranscript` takes in any hash function implementing `Digest`, offering a
secure transcript format around it. All items are prefixed by a flag, denoting
their type, and their length.

`MerlinTranscript` was used to justify the API, and if any issues existed with
`DigestTranscript`, enable a fallback. It was also meant as a way to be
compatible with existing Rust projects using `merlin`.

This library was
[audited by Cypher Stack in March 2023](https://github.com/serai-dex/serai/raw/e1bb2c191b7123fd260d008e31656d090d559d21/audits/Cypher%20Stack%20crypto%20March%202023/Audit.pdf),
culminating in commit
[669d2dbffc1dafb82a09d9419ea182667115df06](https://github.com/serai-dex/serai/tree/669d2dbffc1dafb82a09d9419ea182667115df06).
Any subsequent changes have not undergone auditing.

This library is usable under no_std.
