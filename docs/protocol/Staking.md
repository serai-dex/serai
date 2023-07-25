# Staking

> **_NOTE:_** Delegation has been disabled until further consideration. This is because it could break our security model. A validator can hold up to 66% of their bonded collateral. If they are delegated bonded collateral, they could hold much more than their personal 66%. For example, if a validator has bonded $100 worth of SRI, they can hold up to $66 worth of BTC, ETH, XMR and DAI combined. If they were delegated another $900 worth of SRI, they can hold up to $660 worth of assets. At this point, if they stole the $660 worth of assets, they’d only personally lose $100 worth of SRI.

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
