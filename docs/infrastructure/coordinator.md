---
title: Coordinator
layout: default
nav_order: 3
parent: Infrastructure
---

The coordinator is a local service which communicates with other validators'
coordinators. It provides a verifiable broadcast layer for various consensus
messages, such as agreement on external blockchains, key generation and signing
protocols, and the latest Serai block.

The verifiable broadcast layer is implemented via a blockchain, referred to as a
Tributary, which is agreed upon using Tendermint consensus. This consensus is
not as offered by Tendermint Core/CometBFT, as used in the Cosmos SDK
(historically/presently), yet by our own implementation designed to be used as a
library and not as another daemon. Tributaries are ephemeral, only used by the
current validators, and deleted upon the next epoch. All of the results from it
are verifiable via the external network and the Serai blockchain alone.
