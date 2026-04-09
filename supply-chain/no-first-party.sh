#!/bin/sh

# `cargo vet` assumes all non-`crates.io` dependencies are first-party and
# therefore trusted. Due to our extensive usage of non-`crates.io`
# dependencies, we disagree with this policy and require no crates are
# identified are first-party.
#
# Unfortunately, `cargo vet` does not provide this functionality and the only
# way to mitigate it is to explicitly define all 'first-party' crates as
# third-party. Because there's no builtin way to enforce this, we use the
# following `sh` script to do so.

# Fetch the graph
GRAPH=$(cargo vet dump-graph --depth first-party)
# Jump to its start
SUBGRAPH_START=$(echo "$GRAPH" | grep -n "^[[:space:]]*subgraph first-party$" | cut -d':' -f1)
GRAPH=$(echo "$GRAPH" | tail -n+"$SUBGRAPH_START")
# Filter to its end
SUBGRAPH_END=$(echo "$GRAPH" | grep -n "^[[:space:]]*end$" | head -n1 | cut -d':' -f1)
GRAPH=$(echo "$GRAPH" | head -n"$SUBGRAPH_END")
# Assert this is empty (just the start and end lines)
LINES=$(echo "$GRAPH" | wc -l)
[ "$LINES" -eq 2 ]
