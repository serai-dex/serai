---
title: Protocol Changes
layout: default
nav_order: 5
---

# Protocol Changes

The protocol has no central authority nor organization nor actors (such as
liquidity providers/validators) who can compel new protocol rules. The Serai
protocol is as-written with all granted functionality and declared rules
present.

Validators are explicitly granted the ability to signal for two things to occur:

### 1) Halt another validator set.

This will presumably occur if another validator set turns malicious and is the
expected incident response in order to apply an economic penalty of ideally
greater value than damage wrecked. Halting a validator set prevents further
publication of `Batch`s, preventing improper actions on the Serai blockchain,
and preventing validators from unstaking (as unstaking only occurs once future
validator sets have accepted responsibility, and accepting responsibility
requires `Batch` publication). This effectively burns the malicious validators'
stake.

### 2) Retire the protocol.

A supermajority of validators may favor a signal (an opaque 32-byte ID). A
common signal gaining sufficient favor will cause the protocol to stop producing
blocks in two weeks.

Nodes will presumably, as individual entities, hard fork to new consensus rules.
These rules presumably will remove the rule to stop producing blocks in two
weeks, they may declare new validators, and they may declare new functionality
entirely.

While nodes individually hard fork, across every hard fork the state of the
various `sriXYZ` coins (such as `sriBTC`, `sriETH`, `sriDAI`, and `sriXMR`)
remains intact (unless the new rules modify such state). These coins can still
be burned with instructions (unless the new rules prevent that) and if a
validator set doesn't send `XYZ` as expected, they can be halted (effectively
burning their `SRI` stake). Accordingly, every node decides if and how to future
participate, with the abilities and powers they declare themselves to have.
