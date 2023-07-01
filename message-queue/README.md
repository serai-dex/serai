# Message Log

A message log for various services to communicate over.

Each message is checked to be of the claimed origin. Then, it's added to the
recipient's message queue. This queue is sequentially handled, FIFO, only
dropping messages once the recipient acknowledges it's been handled.

A client which publishes an event specifies its own ID for the publication. If
multiple publications with the same ID occur, they are assumed repeats and
dropped.

This library always panics as its error-cases should be unreachable, given its
intranet status.
