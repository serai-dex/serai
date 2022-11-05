# Message Box

A simple message encryption and authentication wrapper for internal use. It's
intended to protect against a single compromised service from abusing its
networked state to gain privileges not granted to it, while also protecting
against logs, packet captures, and some degree of MITM attacks.
