# Message Queue

A message queue for various services to communicate over.

### Functionality

Messages are queued in a first in, first out (FIFO) fashion.

When queued, the sender specifies the message's 'intent' for the publication.
Only the first message with a specific intent will be handled. This allows
services which are unsure if they sent a message (such as ones which
unexpectedly restarted) to send a message again, without fear of it being
handled multiple times or risk of equivocating.

When fetched, the recipient will fetch the next message they have yet to
acknowledge. This ensures a recipient who unexpectedly restarts while receiving
a message will still receive _and handle_ the message. Once handled, the
explicit acknowledgment is used to inform the Message Queue not to continue to
yield that message.

### Authentication and Confidentiality

Each message is checked to be of the claimed origin before being added to the
recipient's message queue. Additionally, when the recipient receives the
message, their `Client` verifies the signature to ensure it isn't a forgery
from the Message Queue itself.

Confidentiality is a non-goal of this service. Messages are not expected to
contain any secret or private data, or if they do, they are supposed to handle
its confidentiality themselves. In practice, this is seen with how the
Coordinator receives DKG messages from over the network, yet the messages
themselves have secret shares _encrypted to a key only the processor has_. This
allows the Coordinator to forward the message via the Message Queue, without
the Message Queue ever handling sensitive data (and having to consider
confidentiality).

### Integration

The `message-queue-client` crate allows making requests to the Message Queue.
Clients SHOULD follow the following pattern however.

- Fetch from Message Queue
- Store locally, committing the database transaction
- Acknowledge to Message Queue

This pattern ensures the message is received to the recipient (making it safe
to acknowledge) and allows handling the message with solely transactions over
the service's internal database (without any sockets). Additionally, if a
message is stored but a restart occurs before the message is acknowledged, the
recipient is able to identify that on the next fetch, it is being delivered a
message it's already seen.

### Operation

Due to how the intent functionality is designed, the Message Queue experiences
_unbounded database growth_ with no pruning. Intents are on purposely kept
concise, being a label about the data and not the data itself, to minimize
this. This is [tracked](https://github.com/serai-dex/serai/issues/819) to be
improved in the future.

The messages are never read again after being acknowledged and from a design
standpoint, may be immediately pruned. They are kept in case they're necessary
for inspection, but with a threshold which may be tuned by the server's
`MESSAGE_RETENTION` environment variable, specifying how many historic messages
to keep per queue (`10_000` by default).

The Message Queue does not allow resetting a queue's nonce and if a recipient
is reset, it will not be able to receive the historical messages it presumably
needs for its own operation. Similarly, if the Message Queue is reset (or even
rolled back), it is unsafe for further usage with its existing connections.

### Internals

The message format is somewhat over-engineered. Practically, all messages will
be between a processor and the Coordinator, which the server enforces with a
XOR clause (that exclusively one of the sender, recipient is the Coordinator).
Despite this, the syntax does not so restrict this in case the service layout
changes or is extended in the future.

Additionally, messages constantly re-declare who they're from, despite how that
should be consistent to the connection. This allows the connections to be
stateless, and the marginal extra bandwidth is considered a non-issue (as these
sockets should be over the local network).
