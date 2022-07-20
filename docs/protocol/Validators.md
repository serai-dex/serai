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
`validator`'s bond. If `validator`'s bond is not a multiple of the validator
set's bond, it is queued, and will become actively delegated when another
delegator reduces their bond.

Note: At launch, only `validator`'s manager will be able to delegate to
`validator`, and only in multiples of the validator set's bond.

### Undelegate (message)

  - `delegator` (signer):  Address removing delegated funds from `validator`.
  - `validator` (address): Registered validator no longer being delegated to.
  - `amount`    (Amount):  Amount of funds no longer being delegated to
`validator`.

If a sufficient amount of funds are queued, the `validator`'s operation
continues normally, shifting in queued funds. If the `validator` falls below a
multiple of the validator set's bond, they will lose a key share at the next
churn. Only then will this undelegation process, unless another party delegates,
forming a sufficient queue.

Note: At launch, only multiples of the validator set's bond will be valid.

### Resign (message)

  - `validator` (address): Validator being removed from the pool/candidacy.
  - `manager`   (signer):  Manage of `validator`.

If `validator` is active, they will be removed at the next churn. If they are
solely a candidate, they will no longer be eligible for delegations. All bond is
refunded after their removal.
