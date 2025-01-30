# Serai DB

An inefficient, minimal abstraction around databases.

The abstraction offers `get`, `put`, and `del` with helper functions and macros
built on top. Database iteration is not offered, forcing the caller to manually
implement indexing schemes. This ensures wide compatibility across abstracted
databases.
