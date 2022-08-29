# Minimal Ed448

Inefficient, barebones implementation of Ed448 bound to the ff/group API,
rejecting torsion to achieve a PrimeGroup definition. This likely should not be
used and was only done so another library under Serai could confirm its
completion. It is minimally tested, yet should be correct for what it has.
Multiple functions remain unimplemented.

constant time and no_std.
