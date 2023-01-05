# Staking

Serai's staking pallet offers a DPoS system. All stake which enters the system
is delegated somewhere. Delegates can then bond their stake to different
validator sets, justifying their inclusion and providing financial security.

Delegators may transfer stake whenever, so long as that stake isn't actively
bonded. Delegators may also unstake whenever, so long as the prior condition
is still met.

### Stake (message)

  - `delegate` (Address): Address to delegate the newly added stake to.
  - `amount`   (Amount):  Amount to stake and delegate.

### Unstake (message)

  - `delegate` (Address): Address the stake is currently delegated to.
  - `amount`   (Amount):  Amount to unstake.
