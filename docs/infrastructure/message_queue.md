---
title: Message Queue
layout: default
nav_order: 1
parent: Infrastructure
---

# Message Queue

The Message Queue is a microservice to authenticate and relay messages between
services. It offers just three functions:

1) Queue a message.

2) Receive the next message.

3) Acknowledge a message, removing it from the queue.

This ensures messages are delivered between services, with their order
preserved. This also ensures that if a service reboots while handling a message,
it'll still handle the message once rebooted (and the message will not be lost).

The Message Queue also aims to offer increased liveliness and performance.
If services directly communicated, the rate at which one service could operate
would always be bottlenecked by the service it communicates with. If the
receiving service ever went offline, the sending service wouldn't be able to
deliver messages until the receiver came back online, halting its own work. By
defining a dedicated microservice, with a lack of complex logic, it's much less
likely to go offline or suffer from degraded performance.
