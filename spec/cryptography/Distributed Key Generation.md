# Distributed Key Generation

Serai uses a modification of the one-round Distributed Key Generation described
in the [eVRF](https://eprint.iacr.org/2024/397) paper. We only require a
threshold to participate, sacrificing unbiased for robustness, and implement a
verifiable encryption scheme such that anyone can can verify a ciphertext
encrypts the expected secret share.
