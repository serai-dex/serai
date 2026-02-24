# Economics

The economics of the Serai codebase are delineated into two different eras:

1) Pre-economic security.

   Any validator set has yet to achieve economic security.

2) Post-economic security.

    All validator sets have achieved economic security.

These two eras have vastly different considerations and accordingly each have
their own set of rules. They both occur _after_ the protocol's genesis, which
can be itself considered its own era if one desires to but is not here.

Note for the entirety of this document, one day is considered as exactly 24
hours.

## Genesis

At genesis, a set of genesis nodes (presumably community leaders sufficiently
trusted) will start the network. They will perform a DKG and publish the initial
addresses for Serai (over Bitcoin, Ethereum, and Monero) to receive coins with
(BTC, ETH, DAI, and XMR, further referred to with indifference as XYZ).

```
GENESIS_SRI = 100,000,000.000000000 SRI
GENESIS_LIQUIDITY_TIME = 30 days
```

Over `GENESIS_LIQUIDITY_TIME`, any user will be able to provide XYZ. At the end
of `GENESIS_LIQUIDITY_TIME`, the validators will oraclize the value of 1 XYZ
in terms of 0.00000001 BTC (except for BTC). With the value of `sriXYZ`
considered equivalent to the value of `XYZ`, the value of each pool is
determined. `GENESIS_SRI` is proportionately distributed.

With the SRI distributed to the pools, the required amount of SRI for a
validator set to be considered as economically secure can be calculated (as
detailed in following sections). The amount of SRI which must be allocated for
a key share is determined such that for `g` genesis validators,
`(((2 * g) + 1) * allocation_per_key_share) > economic_security_requirement`.
This ensures at least one genesis validator is require to participate in every
signing operation until the network is economically secure. It is potentially
excessive in that liquidity may be added to a pool during genesis, then removed
pre-economic security, without the allocation per key share value decreasing
proportionately however. This is accepted as an oddity.

Genesis is now complete. Allocating stake and swaps become available.

## Pre-economic Security

### Liquidity Providers

Liquidity may not be added to the pools during this era.

Due to Serai's pools premised upon the `x * y = k` formula, for
`M XYZ : N SRI`, the only way for the XYZ portion to decrease is for SRI
exogenous to the pool to be introduced. If SRI is swapped out from the pools,
and swapped back in, it has a neutral effect (slightly in favor to the pool due
to fees) and accordingly isn't considered exogenous.

Exogenous SRI has four possible sources:

1) Circulating SRI.

    There will be no emissions of SRI during this era which aren't immediately
    allocated as stake.

2) Removed liquidity.

    All liquidity removed during this era will burn the SRI airdropped to it in
    order to form the liquidity position.

3) Removed stake.

    Due to the lack of unused capacity in the economic security, there is an
    inability to unstake SRI. If any individual network has achieved unused
    capacity, unstaking still is not allowed so long as any network has yet to.

4) Intra-pool SRI movement.

    For coins sriXYZ, sriABC, the sriXYZ pool may `+sriXYZ, -SRI`. This enables
    `+SRI, -sriABC` in the sriABC pool. To resolve this, each pool tracks
    `+-sriXYZ` and `+-sriSRI` received from such swaps. When an sriXYZ
    liquidity provider removes their liquidity, they do not receive the
    additional sriXYZ in question. When an sriABC liquidity provider removes
    their liquidity, they do receive the SRI in question. This enables them to
    swap it to the sriXYZ and recoup approximate value, barring fees,
    sriABC-sriXYZ price fluctuations, slippage, etc.

Accordingly, exogenous SRI is considered managed, with the intention being for
genesis liquidity providers who remove their liquidity during the pre-economic
security era to receive value at least approximate to the amount of sriXYZ
initially added as liquidity.

### Swap to Staked SRI

At the median quote, any external actor may swap XYZ to SRI outside of the
pools. This SRI would be freshly minted and immediately staked to a validator
within a set for an external network. The XYZ received would be used to form
protocol-owned liquidity, yet removed genesis liquidity will explicitly not
have their XYZ increased in response to this _despite_ the pool's XYZ
increasing (while its SRI remains constant). This prevents an adversary from
providing liquidity at genesis, swapping to staked SRI, before removing their
liquidity to earn staked SRI at a discount proportional to the percentage of
liquidity they provided.

This policy, combined with the lack of emissions and fees to liquidity
providers in the pre-economic security era, leaves the incentive for liquidity
provides as the airdropped SRI.

### Emissions

Emissions only start after genesis.

```
INITIAL_PERIOD = 30 days
INITIAL_REWARD_PER_BLOCK = 100,000 SRI / (1 day / TARGET_BLOCK_TIME)
LITERAL_STAKE_REQUIRED = 1.5 * sri_in_pools()
EXTERNAL_STAKE_BUFFER = 0.2
EXTERNAL_STAKE_REQUIRED = LITERAL_STAKE_REQUIRED * (1 + EXTERNAL_STAKE_BUFFER)
SERAI_VALIDATORS_DESIRED_PERCENTAGE = 0.2
STAKE_DESIRED = EXTERNAL_STAKE_REQUIRED / (1 - SERAI_VALIDATORS_DESIRED_PERCENTAGE)
SERAI_VALIDATORS_STAKE_DESIRED = SERAI_VALIDATORS_DESIRED_PERCENTAGE * STAKE_DESIRED
SECURE_BY = 365 days
```

`CURRENT_STAKE` is the amount of stake from each external network, capped at the
amount needed for each external network to be secure (so a validator set with
unused capacity only counts for the amount required to be secure).

The block reward from genesis till the end of `INITIAL_PERIOD` is fixed to
`INITIAL_REWARD`. Afterwards, the block reward is
`(STAKE_DESIRED - CURRENT_STAKE) / blocks_until(SECURE_BY)`.

This ensures economic security by the specified date. As economic security by
printing SRI is undesirable, the amount of economic security so achieved is a
function of necessity due to lack of interest in staking.

Emissions are distributed to each validator set as a function of their distance
from economic security. For the Serai validator set, which does not have a
literal evaluation of this, `SERAI_VALIDATORS_STAKE_DESIRED` is used as the
value required to be considered economically secure.

## Post-economic Security

### Liquidity Providers

```
GENESIS_TRICKLE_FEED = 180 days
```

Liquidity may be added as the capacity allows.

When genesis liquidity is removed, whereas prior the provider would not receive
additional sriXYZ nor airdropped SRI, they may now receive
`days_since_economic_security().min(GENESIS_TRICKLE_FEED) / GENESIS_TRICKLE_FEED`
of the additional sriXYZ/airdropped SRI.

### Addition of Coins

While liquidity may only be added as per the capacity in the economic security,
this leaves the minting of coins undiscussed. The goal of Serai, in general, is
to always allow minting coins as necessary to perform swaps and ensure the
pools' quotes are consistent (which requires the ability to add, remove
liquidity, interact with external entities, and perform swaps). Unfortunately,
the ability for a malicious validator set to arbitrarily mint sriEXT would
allow them to drain the corresponding liquidity pool of its SRI. This offers a
profit incentive of approximately twice the value of the external coins in the
liquidity pool, despite economic security being calculated regarded solely the
value of the external coins in the pool.

To mitigate this, once a network has achieved economic security, the minting of
_any_ external coins is only allowed so long as the associated validator set is
able to provide security for them _sans additional buffer_. This also means
additional liquidity will be rejected before minting of coins at all is
rejected, allowing swaps to continue to be enabled even when adding liquidity
is no longer.

This does mean, for a validator set whose economic security has low capacity,
floating coins (coins added to the network but outside of a liquidity pool) can
further endanger the economic security. To this end, it's left to the
participants who added coins to perform their own considerations of risk and
remove them per their evaluation.

As a malicious validator set who does arbitrarily mint sriEXT to swap for SRI
would drive the quote down, raising the capacity, the economic security oracle
will only consider the _highest_ observed median price over an extended window
of time.

Distinctly, two side effects can be noted:

- The potential inability to add coins, to swap to them to SRI, enacts a
  circuit breaker such that the radical decline in value for a coin may not be
  recognizable on the Serai network.

- An adversary who pays the opportunity cost of adding coins to Serai, and
  bears the associated risk, is able to tie up capacity _without_ performing a
  service such as providing liquidity. This is unfortunate but accepted for the
  time being, where a network which is unable to fulfill its purpose can be
  retired in favor of a new ruleset, as possible via Signals.

### Emissions

```
BLOCK_REWARD = 20,000,000 SRI / (365 days / TARGET_BLOCK_TIME)
```

`BLOCK_REWARD * SERAI_VALIDATORS_DESIRED_PERCENTAGE` is distributed to the Serai
validator set.

External networks have their proportions decided equivalently to the proportions
of their fees. Once the network's proportion is decided, a proportion between
the pool and the validators is decided.

```
DESIRED_UNUSED_CAPACITY = 0.1
CURRENT_DISTRIBUTION = (used_capacity() / capacity_of_network()).min(1)
DESIRED_DISTRIBUTION = 1 - DESIRED_UNUSED_CAPACITY
```

The rewards are distributed between between validators and the liquidity pools
according to the following ratio.

`DESIRED_UNUSED_CAPACITY : (((1 - CURRENT_DISTRIBUTION) * DESIRED_DISTRIBUTION) / CURRENT_DISTRIBUTION)`

The intent is that as the distribution between usage and capacity skews from
the desired distribution, rewards shift to incentivize accordingly.

## Fees

Independent of the era, fees are handled consistently.

The fee rate is localized to each pool with all pools having a 0.3% fee except
the `sriXMR` pool, which has a 1% fee. While aggressive compared to comparables
and centralized exchanges, this is argued as likely lower than the effective
difference between market value out and actual out offered by most instant
exchangers while the protocol near-exclusively offers specific functionality.

Half of the fees are left in the liquidity pool, effectively being distributed
to LPs, while the other half are burnt.

The intention here is to further reward all parties as usage increases. While
burning SRI presumably increases the value of all remaining SRI, this may be
arbitraged away as the LPs suffer impermanent loss. LPs also are presumed to
represent a minority of the network's SRI, so they're not the primary
benefactor to such a scheme. This is why the explicit distribution exists.

Validators are presumed to represent a majority of the network's SRI, and are
entirely denominated in SRI, hence why burning SRI alone is considered
sufficient for them. Additional, in the pre-Economic Security era, burning SRI
within the pools reduces the distance to economic security.

## Social Policy

Serai, as a social system, can be argued to have expectations despite the lack
of any requirements. Regarding the economics, the expectation should be a degree
of change.

As the network grows in volume, or loses users due to the fees, the fees should
be adjusted. As the network non-sustainably incentivizes, or fails to properly
incentivize, the block reward should be adjusted. How fees are distributed
should also be considered, as there is an argument to entirely burn them.

There is also the potential in the future to grow the SRI supply as new
integrations occur. This is left unexplored at this time.
