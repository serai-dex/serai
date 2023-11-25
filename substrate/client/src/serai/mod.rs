use core::ops::Deref;

use thiserror::Error;

use futures::stream::{Stream, StreamExt};

use scale::{Encode, Decode, Compact};
mod scale_value;
pub(crate) use scale_value::{Value, scale_value};

pub use sp_core::{
  Pair as PairTrait,
  sr25519::{Public, Pair},
};

use subxt::{
  error::Error as SubxtError,
  config::{
    Header as HeaderTrait,
    substrate::{BlakeTwo256, SubstrateHeader},
    extrinsic_params::BaseExtrinsicParams,
  },
  rpc::types::{ChainBlock, ChainBlockExtrinsic},
  Config as SubxtConfig, OnlineClient,
};

pub use serai_runtime::primitives;
pub use primitives::{SeraiAddress, Signature, Amount};

pub use serai_runtime as runtime;
use serai_runtime::{
  system::Config, support::traits::PalletInfo as PalletInfoTrait, PalletInfo, Runtime,
};

pub mod coins;
pub use coins::SeraiCoins;
pub mod dex;
pub use dex::SeraiDex;
pub mod in_instructions;
pub use in_instructions::SeraiInInstructions;
pub mod validator_sets;
pub use validator_sets::SeraiValidatorSets;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Encode, Decode)]
pub struct Tip {
  #[codec(compact)]
  pub tip: u64,
}

pub type Header = SubstrateHeader<serai_runtime::BlockNumber, BlakeTwo256>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SeraiConfig;
impl SubxtConfig for SeraiConfig {
  type Hash = <Runtime as Config>::Hash;
  type Hasher = BlakeTwo256;

  type Index = serai_runtime::Nonce;
  type AccountId = <Runtime as Config>::AccountId;
  // TODO: Bech32m
  type Address = SeraiAddress;

  type Header = Header;
  type Signature = Signature;

  type ExtrinsicParams = BaseExtrinsicParams<SeraiConfig, Tip>;
}

#[derive(Debug)]
pub struct Block(ChainBlock<SeraiConfig>);
impl Block {
  fn new(block: ChainBlock<SeraiConfig>) -> Result<Block, SeraiError> {
    for extrinsic in &block.extrinsics {
      if extrinsic.0.len() < 3 {
        Err(SeraiError::InvalidNode)?;
      }
    }
    Ok(Block(block))
  }
  pub fn hash(&self) -> [u8; 32] {
    self.0.header.hash().into()
  }
  pub fn number(&self) -> u64 {
    self.0.header.number
  }

  /// Returns the time of this block, set by its producer, in milliseconds since the epoch.
  pub fn time(&self) -> Result<u64, SeraiError> {
    for extrinsic in &self.0.extrinsics {
      // Inherent/unsigned
      let inherent = (extrinsic.0[0] >> 7) == 0;

      // To timestamp pallet
      use serai_runtime::Timestamp;
      let timestamp =
        extrinsic.0[1] == u8::try_from(PalletInfo::index::<Timestamp>().unwrap()).unwrap();

      // set call
      let set = extrinsic.0[2] == 0;

      if inherent && timestamp && set {
        if extrinsic.0.len() < 4 {
          Err(SeraiError::InvalidNode)?;
        }
        return Ok(
          Compact::<u64>::decode(&mut &extrinsic.0[3 ..]).map_err(|_| SeraiError::InvalidNode)?.0,
        );
      }
    }
    Err(SeraiError::InvalidNode)
  }

  pub fn header(&self) -> &Header {
    &self.0.header
  }
  pub fn transactions(&self) -> &[ChainBlockExtrinsic] {
    &self.0.extrinsics
  }
}

impl Clone for Block {
  fn clone(&self) -> Block {
    Block(ChainBlock::<SeraiConfig> {
      header: self.0.header.clone(),
      extrinsics: self.0.extrinsics.clone(),
    })
  }
}

#[derive(Error, Debug)]
pub enum SeraiError {
  #[error("failed to communicate with serai: {0}")]
  RpcError(SubxtError),
  #[error("serai-client library was intended for a different runtime version")]
  InvalidRuntime,
  #[error("node is faulty")]
  InvalidNode,
}

#[derive(Clone)]
pub struct Serai(OnlineClient<SeraiConfig>);

#[derive(Clone, Copy)]
pub struct TemporalSerai<'a>(pub(crate) &'a Serai, pub(crate) [u8; 32]);

impl Serai {
  pub async fn new(url: &str) -> Result<Self, SeraiError> {
    Ok(Serai(OnlineClient::<SeraiConfig>::from_url(url).await.map_err(SeraiError::RpcError)?))
  }

  fn unsigned(call: &serai_runtime::RuntimeCall) -> Vec<u8> {
    // TODO: Should Serai purge the old transaction code AND set this to 0/1?
    const EXTRINSIC_FORMAT_VERSION: u8 = 4;

    let mut bytes = vec![EXTRINSIC_FORMAT_VERSION];
    bytes.extend(call.encode());
    bytes
  }

  pub fn sign(
    &self,
    signer: &Pair,
    call: &serai_runtime::RuntimeCall,
    nonce: u32,
    tip: Tip,
  ) -> Vec<u8> {
    const SPEC_VERSION: u32 = 1;
    const TX_VERSION: u32 = 1;
    const EXTRINSIC_FORMAT_VERSION: u8 = 4;

    let era = sp_runtime::generic::Era::Immortal;
    let extra = (era, Compact(nonce), tip);
    let genesis = self.0.genesis_hash();
    let mortality_checkpoint = genesis;
    let mut signature_payload =
      (call, extra, SPEC_VERSION, TX_VERSION, genesis, mortality_checkpoint).encode();
    if signature_payload.len() > 256 {
      signature_payload = sp_core::blake2_256(&signature_payload).to_vec();
    }
    let signature = signer.sign(&signature_payload);

    let signed = 1 << 7;
    (signed + EXTRINSIC_FORMAT_VERSION, signer.public(), signature, extra, call).encode()
  }

  pub async fn publish(&self, tx: &[u8]) -> Result<(), SeraiError> {
    let mut length_prefixed = Compact(u32::try_from(tx.len()).unwrap()).encode();
    length_prefixed.extend(tx);
    self
      .0
      .rpc()
      .deref()
      .request::<String>(
        "author_submitExtrinsic",
        subxt::rpc::rpc_params![hex::encode(length_prefixed)],
      )
      .await
      // Drop the hash, which is the hash of the raw extrinsic, as extrinsics are allowed to share
      // hashes and this hash is accordingly useless/unsafe
      // If we are to return something, it should be block included in and position within block
      .map(|_| ())
      .map_err(SeraiError::RpcError)
  }

  pub async fn latest_block_hash(&self) -> Result<[u8; 32], SeraiError> {
    Ok(self.0.rpc().finalized_head().await.map_err(SeraiError::RpcError)?.into())
  }

  pub async fn latest_block(&self) -> Result<Block, SeraiError> {
    Block::new(
      self
        .0
        .rpc()
        .block(Some(self.0.rpc().finalized_head().await.map_err(SeraiError::RpcError)?))
        .await
        .map_err(SeraiError::RpcError)?
        .ok_or(SeraiError::InvalidNode)?
        .block,
    )
  }

  // There is no provided method for this
  // TODO: Add one to Serai
  pub async fn is_finalized(&self, header: &Header) -> Result<Option<bool>, SeraiError> {
    // Get the latest finalized block
    let finalized = self.latest_block_hash().await?.into();
    // If the latest finalized block is this block, return true
    if finalized == header.hash() {
      return Ok(Some(true));
    }

    let Some(finalized) =
      self.0.rpc().header(Some(finalized)).await.map_err(SeraiError::RpcError)?
    else {
      return Ok(None);
    };

    // If the finalized block has a lower number, this block can't be finalized
    if finalized.number() < header.number() {
      return Ok(Some(false));
    }

    // This block, if finalized, comes before the finalized block
    // If we request the hash of this block's number, Substrate will return the hash on the main
    // chain
    // If that hash is this hash, this block is finalized
    let Some(hash) =
      self.0.rpc().block_hash(Some(header.number().into())).await.map_err(SeraiError::RpcError)?
    else {
      // This is an error since there is a block at this index
      Err(SeraiError::InvalidNode)?
    };

    Ok(Some(header.hash() == hash))
  }

  pub async fn block(&self, hash: [u8; 32]) -> Result<Option<Block>, SeraiError> {
    let Some(res) = self.0.rpc().block(Some(hash.into())).await.map_err(SeraiError::RpcError)?
    else {
      return Ok(None);
    };

    // Only return finalized blocks
    if self.is_finalized(&res.block.header).await? != Some(true) {
      return Ok(None);
    }

    Ok(Some(Block::new(res.block)?))
  }

  // Ideally, this would be block_hash, not block_by_number
  // Unfortunately, in order to only operate over only finalized data, we have to check the
  // returned hash is for a finalized block. We can only do that by calling the extensive
  // is_finalized method, which at least requires the header
  // In practice, the block is likely more useful than the header
  pub async fn block_by_number(&self, number: u64) -> Result<Option<Block>, SeraiError> {
    let Some(hash) =
      self.0.rpc().block_hash(Some(number.into())).await.map_err(SeraiError::RpcError)?
    else {
      return Ok(None);
    };
    self.block(hash.into()).await
  }

  /// A stream which yields whenever new block(s) have been finalized.
  pub async fn newly_finalized_block(
    &self,
  ) -> Result<impl Stream<Item = Result<(), SeraiError>>, SeraiError> {
    Ok(self.0.rpc().subscribe_finalized_block_headers().await.map_err(SeraiError::RpcError)?.map(
      |next| {
        next.map_err(SeraiError::RpcError)?;
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
      .map_err(SeraiError::RpcError)
  }

  /// Create a TemporalSerai using whatever is currently the latest block.
  pub async fn with_current_latest_block(&self) -> Result<TemporalSerai, SeraiError> {
    let latest = self.latest_block_hash().await?;
    Ok(TemporalSerai(self, latest))
  }

  /// Returns a TemporalSerai able to retrieve state as of the specified block.
  pub fn as_of(&self, block: [u8; 32]) -> TemporalSerai {
    TemporalSerai(self, block)
  }
}

impl<'a> TemporalSerai<'a> {
  pub fn into_inner(&self) -> &Serai {
    self.0
  }

  async fn events<P: 'static, E: Decode>(
    &self,
    filter: impl Fn(&E) -> bool,
  ) -> Result<Vec<E>, SeraiError> {
    let mut res = vec![];
    for event in self.0 .0.events().at(self.1.into()).await.map_err(SeraiError::RpcError)?.iter() {
      let event = event.map_err(|_| SeraiError::InvalidRuntime)?;
      if PalletInfo::index::<P>().unwrap() == usize::from(event.pallet_index()) {
        let mut with_variant: &[u8] =
          &[[event.variant_index()].as_ref(), event.field_bytes()].concat();
        let event = E::decode(&mut with_variant).map_err(|_| SeraiError::InvalidRuntime)?;
        if filter(&event) {
          res.push(event);
        }
      }
    }
    Ok(res)
  }

  async fn storage<R: Decode>(
    &self,
    pallet: &'static str,
    name: &'static str,
    keys: Option<Vec<Value>>,
  ) -> Result<Option<R>, SeraiError> {
    let storage = self.0 .0.storage();
    #[allow(clippy::unwrap_or_default)]
    let address = subxt::dynamic::storage(pallet, name, keys.unwrap_or(vec![]));
    debug_assert!(storage.validate(&address).is_ok(), "invalid storage address");

    storage
      .at(self.1.into())
      .fetch(&address)
      .await
      .map_err(SeraiError::RpcError)?
      .map(|res| R::decode(&mut res.encoded()).map_err(|_| SeraiError::InvalidRuntime))
      .transpose()
  }

  pub fn coins(self) -> SeraiCoins<'a> {
    SeraiCoins(self)
  }

  pub fn dex(self) -> SeraiDex<'a> {
    SeraiDex(self)
  }

  pub fn in_instructions(self) -> SeraiInInstructions<'a> {
    SeraiInInstructions(self)
  }

  pub fn validator_sets(self) -> SeraiValidatorSets<'a> {
    SeraiValidatorSets(self)
  }
}
