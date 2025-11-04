# eVRF DKG

In 2024, the [eVRF paper](https://eprint.iacr.org/2024/397) was published to
the IACR preprint server. Within it was a one-round unbiased DKG and a
one-round unbiased threshold DKG. Unfortunately, both simply describe
communication of the secret shares as 'Alice sends $s_b$ to Bob'. This causes,
in practice, the need for an additional round of communication to occur where
all participants confirm they received their secret shares.

Within Serai, it was posited to use the same premises as the DDH eVRF itself to
achieve a verifiable encryption scheme. This allows the secret shares to be
posted to any 'bulletin board' (such as a blockchain) and for all observers to
confirm:

- A participant participated
- The secret shares sent can be received by the intended recipient so long as
  they can access the bulletin board

Additionally, Serai desired a robust scheme (albeit with an biased key as the
output, which is fine for our purposes). Accordingly, our implementation
instantiates the threshold eVRF DKG from the eVRF paper, with our own proposal
for verifiable encryption, with the caller allowed to decide the set of
participants. They may:

- Select everyone, collapsing to the non-threshold unbiased DKG from the eVRF
  paper
- Select a pre-determined set, collapsing to the threshold unbaised DKG from
  the eVRF paper
- Select a post-determined set (with any solution for the Common Subset
  problem), allowing achieving a robust threshold biased DKG

Note that the eVRF paper proposes using the eVRF to sample coefficients yet
this is unnecessary when the resulting key will be biased. Any proof of
knowledge for the coefficients, as necessary for their extraction within the
security proofs, would be sufficient.

MAGIC Grants contracted HashCloak to formalize Serai's proposal for a DKG and
provide proofs for its security. This resulted in
[this paper](<./Security Proofs.pdf>).

Our implementation itself is then built on top of the audited
[`generalized-bulletproofs`](https://github.com/kayabaNerve/monero-oxide/tree/generalized-bulletproofs/audits/crypto/generalized-bulletproofs)
and
[`generalized-bulletproofs-ec-gadgets`](https://github.com/monero-oxide/monero-oxide/tree/fcmp%2B%2B/audits/fcmps).

Note we do not use the originally premised DDH eVRF yet the one premised on
elliptic curve divisors, the methodology of which is commented on
[here](https://github.com/monero-oxide/monero-oxide/tree/fcmp%2B%2B/audits/divisors).

Our implementation itself is unaudited at this time however.
