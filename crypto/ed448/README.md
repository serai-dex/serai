# Minimal Ed448

A barebones implementation of Ed448, making use of the
[`group`](https://docs.rs/group) and
[`ciphersuite`](https://docs.rs/ciphersuite) APIs.

Ed448 has a composite order yet this library restricts points to the
prime-order subgroup, as allowing the implementation of
[`PrimeGroup`](https://docs.rs/group/0.13.0/group/prime/trait.PrimeGroup.html).
While incomplete to the complete elliptic curve, this is an intentional
shortcoming due to the expectation the desired usage will be within the
prime-order subgroup, simplifying the overall API.

This library has not been audited. While it is considered complete, and
decently tested, any usage of it should be carefully considered. No guarantees
are made about its safety nor correctness for any regard and this library,
while hosted by Serai, is not covered by its bug bounty program.

This library executes in constant time and supports no-`std`.
