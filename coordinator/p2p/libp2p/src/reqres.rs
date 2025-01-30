use core::{fmt, time::Duration};
use std::io;

use async_trait::async_trait;

use borsh::{BorshSerialize, BorshDeserialize};

use futures_util::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use libp2p::request_response::{
  self, Codec as CodecTrait, Event as GenericEvent, Config, Behaviour, ProtocolSupport,
};
pub use request_response::{InboundRequestId, Message};

use serai_cosign::SignedCosign;

use serai_coordinator_p2p::{Heartbeat, TributaryBlockWithCommit};

/// The maximum message size for the request-response protocol
// This is derived from the heartbeat message size as it's our largest message
pub(crate) const MAX_LIBP2P_REQRES_MESSAGE_SIZE: usize =
  1024 + serai_coordinator_p2p::heartbeat::BATCH_SIZE_LIMIT;

const PROTOCOL: &str = "/serai/coordinator/reqres/1.0.0";

/// Requests which can be made via the request-response protocol.
#[derive(Clone, Copy, Debug, BorshSerialize, BorshDeserialize)]
pub(crate) enum Request {
  /// A heartbeat informing our peers of our latest block, for the specified blockchain, on regular
  /// intervals.
  ///
  /// If our peers have more blocks than us, they're expected to respond with those blocks.
  Heartbeat(Heartbeat),
  /// A request for the notable cosigns for a global session.
  NotableCosigns { global_session: [u8; 32] },
}

/// Responses which can be received via the request-response protocol.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub(crate) enum Response {
  None,
  Blocks(Vec<TributaryBlockWithCommit>),
  NotableCosigns(Vec<SignedCosign>),
}
impl fmt::Debug for Response {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Response::None => fmt.debug_struct("Response::None").finish(),
      Response::Blocks(_) => fmt.debug_struct("Response::Block").finish_non_exhaustive(),
      Response::NotableCosigns(_) => {
        fmt.debug_struct("Response::NotableCosigns").finish_non_exhaustive()
      }
    }
  }
}

/// The codec used for the request-response protocol.
///
/// We don't use CBOR or JSON, but use borsh to create `Vec<u8>`s we then length-prefix. While
/// ideally, we'd use borsh directly with the `io` traits defined here, they're async and there
/// isn't an amenable API within borsh for incremental deserialization.
#[derive(Default, Clone, Copy, Debug)]
pub(crate) struct Codec;
impl Codec {
  async fn read<M: BorshDeserialize>(io: &mut (impl Unpin + AsyncRead)) -> io::Result<M> {
    let mut len = [0; 4];
    io.read_exact(&mut len).await?;
    let len = usize::try_from(u32::from_le_bytes(len)).expect("not at least a 32-bit platform?");
    if len > MAX_LIBP2P_REQRES_MESSAGE_SIZE {
      Err(io::Error::other("request length exceeded MAX_LIBP2P_REQRES_MESSAGE_SIZE"))?;
    }
    // This may be a non-trivial allocation easily causable
    // While we could chunk the read, meaning we only perform the allocation as bandwidth is used,
    // the max message size should be sufficiently sane
    let mut buf = vec![0; len];
    io.read_exact(&mut buf).await?;
    let mut buf = buf.as_slice();
    let res = M::deserialize(&mut buf)?;
    if !buf.is_empty() {
      Err(io::Error::other("p2p message had extra data appended to it"))?;
    }
    Ok(res)
  }
  async fn write(io: &mut (impl Unpin + AsyncWrite), msg: &impl BorshSerialize) -> io::Result<()> {
    let msg = borsh::to_vec(msg).unwrap();
    io.write_all(&u32::try_from(msg.len()).unwrap().to_le_bytes()).await?;
    io.write_all(&msg).await
  }
}
#[async_trait]
impl CodecTrait for Codec {
  type Protocol = &'static str;
  type Request = Request;
  type Response = Response;

  async fn read_request<R: Send + Unpin + AsyncRead>(
    &mut self,
    _: &Self::Protocol,
    io: &mut R,
  ) -> io::Result<Request> {
    Self::read(io).await
  }
  async fn read_response<R: Send + Unpin + AsyncRead>(
    &mut self,
    _: &Self::Protocol,
    io: &mut R,
  ) -> io::Result<Response> {
    Self::read(io).await
  }
  async fn write_request<W: Send + Unpin + AsyncWrite>(
    &mut self,
    _: &Self::Protocol,
    io: &mut W,
    req: Request,
  ) -> io::Result<()> {
    Self::write(io, &req).await
  }
  async fn write_response<W: Send + Unpin + AsyncWrite>(
    &mut self,
    _: &Self::Protocol,
    io: &mut W,
    res: Response,
  ) -> io::Result<()> {
    Self::write(io, &res).await
  }
}

pub(crate) type Event = GenericEvent<Request, Response>;

pub(crate) type Behavior = Behaviour<Codec>;
pub(crate) fn new_behavior() -> Behavior {
  let config = Config::default().with_request_timeout(Duration::from_secs(5));
  Behavior::new([(PROTOCOL, ProtocolSupport::Full)], config)
}
