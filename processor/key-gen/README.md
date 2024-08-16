# Key Generation

This library implements the Distributed Key Generation (DKG) for the Serai
protocol. Two invocations of the eVRF-based DKG are performed, one for Ristretto
(to have a key to oraclize values onto the Serai blockchain with) and one for
the external network's curve.

This library is interacted with via the `serai-processor-messages::key_gen` API.
