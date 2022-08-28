# Unsafe Ed448

Barebones implementation of Ed448 bound to the ff/group API, rejecting torsion.
This should not be used and was only done so another library under Serai could
confirm its completion. Any usage of this library requires the `hazmat` feature.

constant time and no_std with unusable performance. variable time and std with
barely usable (in a PoC environment) performance. Do not use this.
