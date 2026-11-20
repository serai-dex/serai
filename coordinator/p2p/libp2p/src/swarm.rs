use core::{
  pin::Pin,
  task::{Poll, Context},
};
use alloc::sync::Arc;
use std::{
  sync::RwLock,
  collections::{HashSet, HashMap},
  time::{Duration, Instant},
};

use tokio::sync::oneshot;

use serai_task::TaskHandle;

use serai_cosign::SignedCosign;

use tributary_framework::{ReadWriteAsBorsh, Transaction};

use futures_util::Stream as _;
use libp2p::{
  identity::PeerId,
  request_response::OutboundRequestId,
  swarm::{dial_opts::DialOpts, SwarmEvent, Swarm},
};

use serai_coordinator_p2p::{SyncRequest, P2pRecv};

use crate::{
  Peers, BehaviorEvent, Behavior,
  validators::{self, Validators},
  ping,
  reqres::{self, Request, Response},
  gossip,
};

const TIME_BETWEEN_REBUILD_PEERS: Duration = Duration::from_mins(10);
pub(super) const MAX_OUTBOUND_REQUESTS: usize = 64;

pub(super) type OutboundRequest<Tx> = (PeerId, Request, Option<oneshot::Sender<Response<Tx>>>);

trait StaticSendTransaction: 'static + Send + Transaction {}
impl<T: 'static + Send + Transaction> StaticSendTransaction for T {}

pin_project_lite::pin_project! {
  /// A funnel for all the following channels into the `Swarm`.
  struct SwarmFunnel<Tx: StaticSendTransaction> {
    swarm: Swarm<Behavior<Tx>>,

    #[pin]
    validator_changes: async_channel::Receiver<validators::Changes>,

    #[pin]
    to_dial: async_channel::Receiver<DialOpts>,

    #[pin]
    gossip: async_channel::Receiver<gossip::Message<Tx>>,

    #[pin]
    outbound_requests: async_channel::Receiver<OutboundRequest<Tx>>,
    outbound_request_responses: HashMap<OutboundRequestId, oneshot::Sender<Response<Tx>>>,
  }
}

impl<Tx: 'static + Send + Transaction> SwarmFunnel<Tx> {
  /// The segment of the `poll` function which effectively just drains channels into the `Swarm`.
  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) {
    let mut task = self.project();

    // Update the allow list
    while let Poll::Ready(Some(validator_changes)) = task.validator_changes.as_mut().poll_next(cx) {
      let behavior = &mut task.swarm.behaviour_mut().allow_list;
      for removed in validator_changes.removed {
        behavior.disallow_peer(removed);
      }
      for added in validator_changes.added {
        behavior.allow_peer(added);
      }
    }

    // Dial the peers we're instructed to
    while let Poll::Ready(Some(dial_opts)) = task.to_dial.as_mut().poll_next(cx) {
      let _: Result<_, _> = task.swarm.dial(dial_opts);
    }

    // Send gossip out
    while let Poll::Ready(Some(message)) = task.gossip.as_mut().poll_next(cx) {
      let behavior = task.swarm.behaviour_mut();
      let topic = message.topic();

      enum GossipStep {
        Subscribe,
        Publish,
      }
      for step in [GossipStep::Subscribe, GossipStep::Publish] {
        use libp2p::gossipsub::{PublishError, SubscriptionError};

        let result = match step {
          /*
            If we're sending a message for this topic, it's because this topic is relevant to us.
            Subscribe to it.

            TODO: Unsubscribe from topics which we haven't sent on a message on within the last
            day.
          */
          GossipStep::Subscribe => match behavior.gossip.subscribe(&topic) {
            Ok(_newly_subscribed) => Ok(()),
            Err(SubscriptionError::PublishError(err)) => Err(Some(err)),
            Err(SubscriptionError::NotAllowed) => {
              log::warn!("wasn't allowed to subscribe to {topic}");
              Err(None)
            }
          },

          // Once we're subscribed to the topic, publish our message for it
          GossipStep::Publish => match borsh::to_vec(&message) {
            Ok(message) => match behavior.gossip.publish(topic.hash(), message) {
              Ok(_message_id) => Ok(()),
              Err(err) => Err(Some(err)),
            },
            Err(err) => Err(Some(PublishError::TransformFailed(err))),
          },
        };

        // If there was a `PublishError` with publishing our subscription/message, handle it
        match &result {
          Ok(()) | Err(None) => {}
          Err(Some(err)) => match err {
            // TODO: Poke `DialTask` to dial more peers for this if `NoPeersSubscribedToTopic`?
            PublishError::Duplicate | PublishError::NoPeersSubscribedToTopic => {}
            err @ (PublishError::MessageTooLarge |
            PublishError::SigningError(_) |
            PublishError::TransformFailed(_)) => {
              log::warn!("couldn't gossip message due to internal error: {err:?}");
            }
            // TODO: Backpressure this instead of dropping the message
            PublishError::AllQueuesFull(_attempted_peers) => {}
          },
        }

        // If a step failed, don't continue
        if result.is_err() {
          break;
        }
      }
    }

    // Only begin more outbound requests if we have less than the maximum outstanding
    while (task.outbound_request_responses.len() < MAX_OUTBOUND_REQUESTS) &&
      let Poll::Ready(Some((peer, request, response_channel))) =
        task.outbound_requests.as_mut().poll_next(cx)
    {
      let request_id = task.swarm.behaviour_mut().reqres.send_request(&peer, request);
      if let Some(response_channel) = response_channel {
        task.outbound_request_responses.insert(request_id, response_channel);
      }
    }
  }
}

/*
  `SwarmTask` handles everything we need the `Swarm` object for. The goal is to minimize the
  contention on this task. Unfortunately, the `Swarm` object itself is needed for a variety of
  purposes making this a rather large task.

  Responsibilities include:
  - Actually dialing new peers (the selection process occurs in another task)
  - Maintaining the peers structure (as we need the Swarm object to see who our peers are)
  - Gossiping messages
  - Dispatching gossiped messages
  - Sending requests
  - Dispatching responses to requests
  - Dispatching received requests
  - Sending responses
*/
pin_project_lite::pin_project! {
  pub(super) struct SwarmTask<Tx: StaticSendTransaction> {
    dial_task: TaskHandle,
    last_dial_task_run: Instant,

    validators: Arc<RwLock<Validators>>,
    peers: Peers,
    #[pin]
    rebuild_peers: tokio::time::Sleep,

    #[pin]
    funnel: SwarmFunnel<Tx>,

    outstanding_signed_cosigns: Vec<SignedCosign>,
  }
}

impl<Tx: 'static + Send + Transaction> SwarmTask<Tx> {
  fn handle_gossip(
    swarm: &mut Swarm<Behavior<Tx>>,
    event: gossip::Event,
  ) -> Option<serai_coordinator_p2p::Recv<Tx, <Self as P2pRecv<Tx>>::Response>> {
    match event {
      gossip::Event::Message { message, .. } => {
        let Some(message) = ({
          let mut slice = message.data.as_slice();
          let message =
            <gossip::Message<Tx> as borsh::BorshDeserialize>::deserialize_reader(&mut slice);
          message.ok().filter(|_| slice.is_empty())
        }) else {
          // TODO: Penalize the PeerId which created this message, which requires authenticating
          // each message OR moving to explicit acknowledgement before re-gossiping
          None?
        };
        Some(match message {
          gossip::Message::TributaryMessage { tributary, message } => {
            serai_coordinator_p2p::Recv::TributaryMessage(tributary, message)
          }
          gossip::Message::TributaryTransaction {
            tributary,
            transaction: ReadWriteAsBorsh(transaction),
          } => serai_coordinator_p2p::Recv::TributaryTransaction(tributary, transaction),
          gossip::Message::Cosign(signed_cosign) => {
            serai_coordinator_p2p::Recv::SignedCosign(signed_cosign)
          }
        })
      }
      gossip::Event::Subscribed { .. } | gossip::Event::Unsubscribed { .. } => None,
      gossip::Event::GossipsubNotSupported { peer_id } |
      gossip::Event::SlowPeer { peer_id, .. } => {
        let _: Result<_, _> = swarm.disconnect_peer_id(peer_id);
        None
      }
    }
  }

  fn handle_reqres(
    cx: &mut Context<'_>,
    outbound_request_responses: &mut HashMap<OutboundRequestId, oneshot::Sender<Response<Tx>>>,
    outstanding_signed_cosigns: &mut Vec<SignedCosign>,
    event: reqres::Event<Tx>,
  ) -> Option<serai_coordinator_p2p::Recv<Tx, <Self as P2pRecv<Tx>>::Response>> {
    let outstanding_requests_at_start = outbound_request_responses.len();

    let result = match event {
      reqres::Event::Message { message, .. } => match message {
        reqres::Message::Request { request_id: _, request, channel } => Some(match request {
          reqres::Request::SyncRequest(SyncRequest { set, latest_block_hash }) => {
            serai_coordinator_p2p::Recv::SyncRequest(
              SyncRequest { set, latest_block_hash },
              channel,
            )
          }
          reqres::Request::NotableCosigns { global_session } => {
            serai_coordinator_p2p::Recv::NotableCosignsRequest(global_session, channel)
          }
        }),
        reqres::Message::Response { request_id, response } => {
          if let Some(channel) = outbound_request_responses.remove(&request_id) {
            let _: Result<_, _> = channel.send(response);
            None
          } else if let Response::NotableCosigns(signed_cosigns) = response {
            *outstanding_signed_cosigns = signed_cosigns;
            outstanding_signed_cosigns.pop().map(serai_coordinator_p2p::Recv::SignedCosign)
          } else {
            None
          }
        }
      },
      reqres::Event::OutboundFailure { request_id, .. } => {
        // Send None as the response for the request
        if let Some(channel) = outbound_request_responses.remove(&request_id) {
          let _: Result<_, _> = channel.send(Response::None);
        }
        None
      }
      reqres::Event::InboundFailure { .. } | reqres::Event::ResponseSent { .. } => None,
    };

    /*
      If we've responded to an outstanding request, wake ourselves, in case the
      `outbound_requests` channel is backpressured.
    */
    if (outstanding_requests_at_start == MAX_OUTBOUND_REQUESTS) &&
      (outbound_request_responses.len() < outstanding_requests_at_start)
    {
      cx.waker().wake_by_ref();
    }

    result
  }
}

impl<Tx: 'static + Send + Transaction> P2pRecv<Tx> for SwarmTask<Tx> {
  type Response = libp2p::request_response::ResponseChannel<Response<Tx>>;

  fn poll(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<serai_coordinator_p2p::Recv<Tx, Self::Response>> {
    let mut task = self.project();
    task.funnel.as_mut().poll(cx);
    let funnel = task.funnel.project();

    if let Some(signed_cosign) = task.outstanding_signed_cosigns.pop() {
      cx.waker().wake_by_ref();
      return Poll::Ready(serai_coordinator_p2p::Recv::SignedCosign(signed_cosign));
    }

    /*
      Rebuild the peers every 10 minutes.

      This protects against any race conditions/edge cases we have in our logic to track peers,
      along with unrepresented behavior such as when a peer changes the networks they're active
      in. This lets the peer tracking logic simply be 'good enough' to not become horribly
      corrupt over the span of `TIME_BETWEEN_REBUILD_PEERS`.

      We also use this to disconnect all peers who are no longer active in any network.
    */
    while let Poll::Ready(()) = task.rebuild_peers.as_mut().poll(cx) {
      task.rebuild_peers.set(tokio::time::sleep(TIME_BETWEEN_REBUILD_PEERS));
      let validators_by_network = task.validators.read().unwrap().by_network().clone();
      let connected_peers = funnel.swarm.connected_peers().copied().collect::<HashSet<_>>();

      // Build the new peers object
      let mut peers = HashMap::new();
      for (network, validators) in validators_by_network {
        peers.insert(network, validators.intersection(&connected_peers).copied().collect());
      }

      // Write the new peers object
      *task.peers.peers.write().unwrap() = peers;
    }

    // `Swarm: Unpin`
    while let Poll::Ready(Some(event)) = Pin::new(&mut *funnel.swarm).poll_next(cx) {
      match event {
        // New connection, so update peers
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
          let Some(networks) = task.validators.read().unwrap().networks(&peer_id).cloned() else {
            continue;
          };
          let mut peers = task.peers.peers.write().unwrap();
          for network in networks {
            peers.entry(network).or_insert_with(HashSet::new).insert(peer_id);
          }
        }

        // Connection closed, so update peers
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
          let Some(networks) = task.validators.read().unwrap().networks(&peer_id).cloned() else {
            continue;
          };
          let mut peers = task.peers.peers.write().unwrap();
          for network in networks {
            peers.entry(network).or_insert_with(HashSet::new).remove(&peer_id);
          }

          /*
            We want to re-run the dial task, since we lost a peer, in case we should find new
            peers. This opens a DoS where a validator repeatedly opens/closes connections to
            force iterations of the dial task. We prevent this by setting a minimum distance
            since the last explicit iteration.

            This is suboptimal. If we have several disconnects in immediate proximity, we'll
            trigger the dial task upon the first (where we may still have enough peers we
            shouldn't dial more) but not the last (where we may have so few peers left we
            should dial more). This is accepted as the dial task will eventually run on its
            natural timer.
          */
          const MINIMUM_TIME_SINCE_LAST_EXPLICIT_DIAL: Duration = Duration::from_mins(1);
          let now = Instant::now();
          if ((*task.last_dial_task_run) + MINIMUM_TIME_SINCE_LAST_EXPLICIT_DIAL) < now {
            task.dial_task.run_now();
            *task.last_dial_task_run = now;
          }
        }

        SwarmEvent::Behaviour(event) => {
          match event {
            BehaviorEvent::AllowList(event) | BehaviorEvent::ConnectionLimits(event) => {
              // This *is* an exhaustive match as these events are empty enums
              match event {}
            }
            BehaviorEvent::Ping(ping::Event { peer: _, connection, result }) => {
              if result.is_err() {
                funnel.swarm.close_connection(connection);
              }
            }
            BehaviorEvent::Reqres(event) => {
              if let Some(resp) = Self::handle_reqres(
                cx,
                funnel.outbound_request_responses,
                task.outstanding_signed_cosigns,
                event,
              ) {
                cx.waker().wake_by_ref();
                return Poll::Ready(resp);
              }
            }
            BehaviorEvent::Gossip(event) => {
              if let Some(resp) = Self::handle_gossip(funnel.swarm, event) {
                cx.waker().wake_by_ref();
                return Poll::Ready(resp);
              }
            }
          }
        }

        // We don't handle any of these
        SwarmEvent::IncomingConnection { .. } |
        SwarmEvent::IncomingConnectionError { .. } |
        SwarmEvent::OutgoingConnectionError { .. } |
        SwarmEvent::NewListenAddr { .. } |
        SwarmEvent::ExpiredListenAddr { .. } |
        SwarmEvent::ListenerClosed { .. } |
        SwarmEvent::ListenerError { .. } |
        SwarmEvent::Dialing { .. } |
        SwarmEvent::NewExternalAddrCandidate { .. } |
        SwarmEvent::ExternalAddrConfirmed { .. } |
        SwarmEvent::ExternalAddrExpired { .. } |
        SwarmEvent::NewExternalAddrOfPeer { .. } => {}

        // Required as SwarmEvent is non-exhaustive
        _ => log::warn!("unhandled `SwarmEvent`: {event:?}"),
      }
    }

    Poll::Pending
  }

  /// Respond to a [`Recv::NotableCosignsRequest`] with the following cosigns.
  fn notable_cosigns(
    self: Pin<&mut Self>,
    response: Self::Response,
    notable_cosigns: Vec<SignedCosign>,
  ) {
    let _: Result<(), _> = self
      .project()
      .funnel
      .project()
      .swarm
      .behaviour_mut()
      .reqres
      .send_response(response, Response::NotableCosigns(notable_cosigns));
  }

  /// Respond to a [`Recv::SyncRequest`] with the following blocks.
  fn sync(
    self: Pin<&mut Self>,
    response: Self::Response,
    blocks: Vec<serai_coordinator_p2p::CommittedTributaryBlock<Tx>>,
  ) {
    let _: Result<(), _> = self
      .project()
      .funnel
      .project()
      .swarm
      .behaviour_mut()
      .reqres
      .send_response(response, Response::Blocks(blocks));
  }
}

impl<Tx: 'static + Send + Transaction> SwarmTask<Tx> {
  #[expect(clippy::too_many_arguments)]
  pub(super) fn new(
    dial_task: TaskHandle,
    to_dial: async_channel::Receiver<DialOpts>,

    validators: Arc<RwLock<Validators>>,
    validator_changes: async_channel::Receiver<validators::Changes>,
    peers: Peers,

    swarm: Swarm<Behavior<Tx>>,

    gossip: async_channel::Receiver<gossip::Message<Tx>>,

    outbound_requests: async_channel::Receiver<OutboundRequest<Tx>>,
  ) -> Self {
    Self {
      dial_task,
      last_dial_task_run: Instant::now(),

      validators,
      peers,
      rebuild_peers: tokio::time::sleep(TIME_BETWEEN_REBUILD_PEERS),

      funnel: SwarmFunnel {
        swarm,
        validator_changes,
        to_dial,
        gossip,
        outbound_requests,
        outbound_request_responses: HashMap::with_capacity(MAX_OUTBOUND_REQUESTS),
      },

      outstanding_signed_cosigns: vec![],
    }
  }
}
