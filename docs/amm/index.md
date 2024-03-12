---
title: Automatic Market Makers
layout: default
nav_order: 2
---

*text on how AMMs work*

Serai uses a symmetric liquidity pool with the `xy=k` formula.

Concentrated liquidity would presumably offer less slippage on swaps, and there are
[discussions to evolve to a concentrated liquidity/order book environment](https://github.com/serai-dex/serai/issues/420).
Unfortunately, it effectively requires active management of provided liquidity.
This disenfranchises small liquidity providers who may not have the knowledge
and resources necessary to perform such management. Since Serai is expected to
have a community-bootstrapped start, starting with concentrated liquidity would
accordingly be contradictory.
