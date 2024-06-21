use thiserror::Error;

use async_lock::RwLock;
use simple_request::{hyper, Request, Client};

use scale::{Decode, Encode};
use serde::{Serialize, Deserialize, de::DeserializeOwned};

pub use sp_core::{
  Pair as PairTrait,
  sr25519::{Public, Pair},
};

pub use serai_abi as abi;
pub use abi::{primitives, Transaction};
use abi::*;

pub use primitives::{SeraiAddress, Signature, Amount};
use primitives::{Header, NetworkId};

pub mod coins;
pub use coins::SeraiCoins;
pub mod dex;
pub use dex::SeraiDex;
pub mod in_instructions;
pub use in_instructions::SeraiInInstructions;
pub mod validator_sets;
pub use validator_sets::SeraiValidatorSets;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode)]
pub struct Block {
  pub header: Header,
  pub transactions: Vec<Transaction>,
}
impl Block {
  pub fn hash(&self) -> [u8; 32] {
    self.header.hash().into()
  }
  pub fn number(&self) -> u64 {
    self.header.number
  }

  /// Returns the time of this block, set by its producer, in milliseconds since the epoch.
  pub fn time(&self) -> Result<u64, SeraiError> {
    for transaction in &self.transactions {
      if let Call::Timestamp(timestamp::Call::set { now }) = transaction.call() {
        return Ok(*now);
      }
    }
    Err(SeraiError::InvalidNode("no time was present in block".to_string()))
  }
}

#[derive(Error, Debug)]
pub enum SeraiError {
  #[error("failed to communicate with serai")]
  ConnectionError,
  #[error("node is faulty: {0}")]
  InvalidNode(String),
  #[error("error in response: {0}")]
  ErrorInResponse(String),
  #[error("serai-client library was intended for a different runtime version: {0}")]
  InvalidRuntime(String),
}

#[derive(Clone)]
pub struct Serai {
  url: String,
  client: Client,
  genesis: [u8; 32],
}

type EventsInBlock = Vec<frame_system::EventRecord<Event, [u8; 32]>>;
pub struct TemporalSerai<'a> {
  serai: &'a Serai,
  block: [u8; 32],
  events: RwLock<Option<EventsInBlock>>,
}
impl<'a> Clone for TemporalSerai<'a> {
  fn clone(&self) -> Self {
    Self { serai: self.serai, block: self.block, events: RwLock::new(None) }
  }
}

impl Serai {
  pub async fn call<Req: Serialize, Res: DeserializeOwned>(
    &self,
    method: &str,
    params: Req,
  ) -> Result<Res, SeraiError> {
    let request = Request::from(
      hyper::Request::post(&self.url)
        .header("Content-Type", "application/json")
        .body(
          serde_json::to_vec(
            &serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }),
          )
          .unwrap()
          .into(),
        )
        .unwrap(),
    );

    #[derive(Deserialize)]
    pub struct Error {
      message: String,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RpcResponse<T> {
      Ok { result: T },
      Err { error: Error },
    }

    let mut res = self
      .client
      .request(request)
      .await
      .map_err(|_| SeraiError::ConnectionError)?
      .body()
      .await
      .map_err(|_| SeraiError::ConnectionError)?;

    let res: RpcResponse<Res> = serde_json::from_reader(&mut res).map_err(|e| {
      SeraiError::InvalidRuntime(format!(
        "response was a different type than expected: {:?}",
        e.classify()
      ))
    })?;
    match res {
      RpcResponse::Ok { result } => Ok(result),
      RpcResponse::Err { error } => Err(SeraiError::ErrorInResponse(error.message)),
    }
  }

  fn hex_decode(str: String) -> Result<Vec<u8>, SeraiError> {
    (if let Some(stripped) = str.strip_prefix("0x") {
      hex::decode(stripped)
    } else {
      hex::decode(str)
    })
    .map_err(|_| SeraiError::InvalidNode("expected hex from node wasn't hex".to_string()))
  }

  pub async fn block_hash(&self, number: u64) -> Result<Option<[u8; 32]>, SeraiError> {
    let hash: Option<String> = self.call("chain_getBlockHash", [number]).await?;
    let Some(hash) = hash else { return Ok(None) };
    Self::hex_decode(hash)?
      .try_into()
      .map_err(|_| SeraiError::InvalidNode("didn't respond to getBlockHash with hash".to_string()))
      .map(Some)
  }

  pub async fn new(url: String) -> Result<Self, SeraiError> {
    let client = Client::with_connection_pool();
    let mut res = Serai { url, client, genesis: [0xfe; 32] };
    res.genesis = res.block_hash(0).await?.ok_or_else(|| {
      SeraiError::InvalidNode("node didn't have the first block's hash".to_string())
    })?;
    Ok(res)
  }

  fn unsigned(call: Call) -> Transaction {
    Transaction::new(call, None)
  }

  pub fn sign(&self, signer: &Pair, call: Call, nonce: u32, tip: u64) -> Transaction {
    const SPEC_VERSION: u32 = 1;
    const TX_VERSION: u32 = 1;

    let extra = Extra { era: sp_runtime::generic::Era::Immortal, nonce, tip };
    let signature_payload = (
      &call,
      &extra,
      SignedPayloadExtra {
        spec_version: SPEC_VERSION,
        tx_version: TX_VERSION,
        genesis: self.genesis,
        mortality_checkpoint: self.genesis,
      },
    )
      .encode();
    let signature = signer.sign(&signature_payload);

    Transaction::new(call, Some((signer.public().into(), signature, extra)))
  }

  pub async fn publish(&self, tx: &Transaction) -> Result<(), SeraiError> {
    // Drop the returned hash, which is the hash of the raw extrinsic, as extrinsics are allowed
    // to share hashes and this hash is accordingly useless/unsafe
    // If we are to return something, it should be block included in and position within block
    let _: String = self.call("author_submitExtrinsic", [hex::encode(tx.encode())]).await?;
    Ok(())
  }

  async fn active_network_validators(&self, network: NetworkId) -> Result<Vec<Public>, SeraiError> {
    let validators: String = self
      .call("state_call", ["SeraiRuntimeApi_validators".to_string(), hex::encode(network.encode())])
      .await?;
    let bytes = Self::hex_decode(validators)?;
    let r = Vec::<Public>::decode(&mut bytes.as_slice())
      .map_err(|e| SeraiError::ErrorInResponse(e.to_string()))?;
    Ok(r)
  }

  pub async fn latest_finalized_block_hash(&self) -> Result<[u8; 32], SeraiError> {
    let hash: String = self.call("chain_getFinalizedHead", ()).await?;
    Self::hex_decode(hash)?.try_into().map_err(|_| {
      SeraiError::InvalidNode("didn't respond to getFinalizedHead with hash".to_string())
    })
  }

  pub async fn header(&self, hash: [u8; 32]) -> Result<Option<Header>, SeraiError> {
    self.call("chain_getHeader", [hex::encode(hash)]).await
  }

  pub async fn block(&self, hash: [u8; 32]) -> Result<Option<Block>, SeraiError> {
    let block: Option<String> = self.call("chain_getBlockBin", [hex::encode(hash)]).await?;
    let Some(block) = block else { return Ok(None) };
    let Ok(bytes) = Self::hex_decode(block) else {
      Err(SeraiError::InvalidNode("didn't return a hex-encoded block".to_string()))?
    };
    let Ok(block) = Block::decode(&mut bytes.as_slice()) else {
      Err(SeraiError::InvalidNode("didn't return a block".to_string()))?
    };
    Ok(Some(block))
  }

  pub async fn latest_finalized_block(&self) -> Result<Block, SeraiError> {
    let latest = self.latest_finalized_block_hash().await?;
    let Some(block) = self.block(latest).await? else {
      Err(SeraiError::InvalidNode("node didn't have a latest block".to_string()))?
    };
    Ok(block)
  }

  // There is no provided method for this
  // TODO: Add one to Serai
  pub async fn is_finalized(&self, header: &Header) -> Result<bool, SeraiError> {
    // Get the latest finalized block
    let finalized = self.latest_finalized_block_hash().await?;
    // If the latest finalized block is this block, return true
    if finalized == header.hash().as_ref() {
      return Ok(true);
    }

    let Some(finalized) = self.header(finalized).await? else {
      Err(SeraiError::InvalidNode("couldn't get finalized header".to_string()))?
    };

    // If the finalized block has a lower number, this block can't be finalized
    if finalized.number < header.number {
      return Ok(false);
    }

    // This block, if finalized, comes before the finalized block
    // If we request the hash of this block's number, Substrate will return the hash on the main
    // chain
    // If that hash is this hash, this block is finalized
    let Some(hash) = self.block_hash(header.number).await? else {
      // This is an error since there is a finalized block at this index
      Err(SeraiError::InvalidNode(
        "couldn't get block hash for a block number below the finalized block".to_string(),
      ))?
    };

    Ok(header.hash().as_ref() == hash)
  }

  pub async fn finalized_block_by_number(&self, number: u64) -> Result<Option<Block>, SeraiError> {
    let hash = self.block_hash(number).await?;
    let Some(hash) = hash else { return Ok(None) };
    let Some(block) = self.block(hash).await? else { return Ok(None) };
    if !self.is_finalized(&block.header).await? {
      return Ok(None);
    }
    Ok(Some(block))
  }

  /*
  /// A stream which yields whenever new block(s) have been finalized.
  pub async fn newly_finalized_block(
    &self,
  ) -> Result<impl Stream<Item = Result<(), SeraiError>>, SeraiError> {
    Ok(self.0.rpc().subscribe_finalized_block_headers().await
    .map_err(|_| SeraiError::ConnectionError)?.map(
      |next| {
        next.map_err(|_| SeraiError::ConnectionError)?;
        Ok(())
      },
    ))
  }

  pub async fn nonce(&self, address: &SeraiAddress) -> Result<u32, SeraiError> {
    self
      .0
      .rpc()
      .system_account_next_index(&sp_core::sr25519::Public(address.0).to_string())
      .await
      .map_err(|_| SeraiError::ConnectionError)
  }
  */

  /// Create a TemporalSerai bound to whatever is currently the latest finalized block.
  ///
  /// The binding occurs at time of call. This does not track the latest finalized block and update
  /// itself.
  pub async fn as_of_latest_finalized_block(&self) -> Result<TemporalSerai, SeraiError> {
    let latest = self.latest_finalized_block_hash().await?;
    Ok(TemporalSerai { serai: self, block: latest, events: RwLock::new(None) })
  }

  /// Returns a TemporalSerai able to retrieve state as of the specified block.
  pub fn as_of(&self, block: [u8; 32]) -> TemporalSerai {
    TemporalSerai { serai: self, block, events: RwLock::new(None) }
  }

  /// Return the P2P Multiaddrs for the validators of the specified network.
  pub async fn p2p_validators(
    &self,
    network: NetworkId,
  ) -> Result<Vec<multiaddr::Multiaddr>, SeraiError> {
    self.call("p2p_validators", network).await
  }
}

impl<'a> TemporalSerai<'a> {
  async fn events<E>(
    &self,
    filter_map: impl Fn(&Event) -> Option<E>,
  ) -> Result<Vec<E>, SeraiError> {
    let mut events = self.events.read().await;
    if events.is_none() {
      drop(events);
      let mut events_write = self.events.write().await;
      if events_write.is_none() {
        *events_write = Some(self.storage("System", "Events", ()).await?.unwrap_or(vec![]));
      }
      drop(events_write);
      events = self.events.read().await;
    }

    let mut res = vec![];
    for event in events.as_ref().unwrap() {
      if let Some(event) = filter_map(&event.event) {
        res.push(event);
      }
    }
    Ok(res)
  }

  async fn storage<K: Encode, R: Decode>(
    &self,
    pallet: &'static str,
    name: &'static str,
    key: K,
  ) -> Result<Option<R>, SeraiError> {
    // TODO: Make this const?
    let mut full_key = sp_core::hashing::twox_128(pallet.as_bytes()).to_vec();
    full_key.extend(sp_core::hashing::twox_128(name.as_bytes()));
    full_key.extend(key.encode());

    let res: Option<String> =
      self.serai.call("state_getStorage", [hex::encode(full_key), hex::encode(self.block)]).await?;
    let Some(res) = res else { return Ok(None) };
    let res = Serai::hex_decode(res)?;
    Ok(Some(R::decode(&mut res.as_slice()).map_err(|_| {
      SeraiError::InvalidRuntime(format!(
        "different type present at storage location, raw value: {}",
        hex::encode(res)
      ))
    })?))
  }

  pub fn coins(&'a self) -> SeraiCoins<'a> {
    SeraiCoins(self)
  }

  pub fn dex(&'a self) -> SeraiDex<'a> {
    SeraiDex(self)
  }

  pub fn in_instructions(&'a self) -> SeraiInInstructions<'a> {
    SeraiInInstructions(self)
  }

  pub fn validator_sets(&'a self) -> SeraiValidatorSets<'a> {
    SeraiValidatorSets(self)
  }
}
