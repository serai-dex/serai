# Validators

### Register (message)

- `validator` (signer): Address which will be the validator on Substrate.
- `manager`   (signer): Address which will manage this validator.
- `set`       (VS):     Validator set being joined.

Marks `validator` as a validator candidate for the specified validator set,
enabling delegation.

### Delegate (message)

  - `delegator` (signer):  Address delegating funds to `validator`.
  - `validator` (address): Registered validator being delegated to.
  - `amount`    (Amount):  Amount of funds being delegated to `validator`.

Delegated funds will be removed from `delegator`'s wallet and moved to
`validator`'s bond. `amount` must be a multiple of the validator set's bond, and
`delegator` must be `validator`'s manager.

### Undelegate (message)

  - `delegator` (signer):  Address removing delegated funds from `validator`.
  - `validator` (address): Registered validator no longer being delegated to.
  - `amount`    (Amount):  Amount of funds no longer being delegated to
`validator`.

`delegator` must be `validator`'s manager, and `amount` must be a multiple of
the validator set's bond. `validator` is scheduled to lose an according amount
of key shares at the next churn, and once they do, the specified amount will be
moved from `validator`'s bond to `delegator`'s wallet.

`validator`'s bond must be at least the validator set's bond after the
undelegation.

### Resign (message)

  - `manager`   (signer):  Manager of `validator`.
  - `validator` (address): Validator being removed from the pool/candidacy.

If `validator` is active, they will be removed at the next churn. If they are
solely a candidate, they will no longer be eligible for delegations. All bond is
refunded after their removal.
