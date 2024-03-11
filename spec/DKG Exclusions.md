Upon an issue with the DKG, the honest validators must remove the malicious
validators. Ideally, a threshold signature would be used, yet that would require
a threshold key (which would require authentication by a MuSig signature). A
MuSig signature which specifies the signing set (or rather, the excluded
signers) achieves the most efficiency.

While that resolves the on-chain behavior, the Tributary also has to perform
exclusion. This has the following forms:

1) Rejecting further transactions (required)
2) Rejecting further participation in Tendermint

With regards to rejecting further participation in Tendermint, it's *ideal* to
remove the validator from the list of validators. Each validator removed from
participation, yet not from the list of validators, increases the likelihood of
the network failing to form consensus.

With regards to the economic security, an honest 67% may remove a faulty
(explicitly or simply offline) 33%, letting 67% of the remaining 67% (4/9ths)
take control of the associated private keys. In such a case, the malicious
parties are defined as the 4/9ths of validators with access to the private key
and the 33% removed (who together form >67% of the originally intended
validator set and have presumably provided enough stake to cover losses).
