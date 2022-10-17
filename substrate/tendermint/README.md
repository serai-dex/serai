# Tendermint

An implementation of the Tendermint state machine in Rust.

This is solely the state machine, intended to be mapped to any arbitrary system.
It supports an arbitrary hash function, signature protocol, and block
definition accordingly. It is not intended to work with the Cosmos SDK, solely
be an implementation of the
[academic protocol](https://arxiv.org/pdf/1807.04938.pdf).

### Paper

The [paper](https://arxiv.org/abs/1807.04938) describes the algorithm with
pseudocode on page 6. This pseudocode is written as a series of conditions for
advancement. This is extremely archaic, as its a fraction of the actually
required code. This is due to its hand-waving away of data tracking, lack of
comments (beyond the entire rest of the paper, of course), and lack of
specification regarding faulty nodes.

While the "hand-waving" is both legitimate and expected, as it's not the paper's
job to describe a full message processing loop nor efficient variable handling,
it does leave behind ambiguities and annoyances, not to mention an overall
structure which cannot be directly translated. This section is meant to be a
description of it as used for translation.

The included pseudocode segments can be minimally described as follows:

```
01-09 Init
10-10 StartRound(0)
11-21 StartRound
22-27 Fresh proposal
28-33 Proposal building off a valid round with prevotes
34-35 2f+1 prevote -> schedule timeout prevote
36-43 First proposal with prevotes -> precommit Some
44-46 2f+1 nil prevote -> precommit nil
47-48 2f+1 precommit -> schedule timeout precommit
49-54 First proposal with precommits -> finalize
55-56 f+1 round > local round, jump
57-60 on timeout propose
61-64 on timeout prevote
65-67 on timeout precommit
```
