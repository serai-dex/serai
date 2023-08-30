use thiserror::Error;

use scale::{Encode, Decode, Compact};
mod scale_value;
pub(crate) use scale_value::{Value, Composite, scale_value, scale_composite};

pub use sp_core::{
  Pair as PairTrait,
  sr25519::{Public, Pair},
};

pub use subxt;
use subxt::{
  error::Error as SubxtError,
  utils::Encoded,
  config::{
    Header as HeaderTrait,
    substrate::{BlakeTwo256, SubstrateHeader},
    extrinsic_params::{BaseExtrinsicParams, BaseExtrinsicParamsBuilder},
  },
  tx::{Signer, Payload, TxClient},
  rpc::types::{ChainBlock, ChainBlockExtrinsic},
  Config as SubxtConfig, OnlineClient,
};

pub use serai_runtime::primitives;
pub use primitives::{SeraiAddress, Signature, Amount};

pub use serai_runtime as runtime;
use serai_runtime::{
  system::Config, support::traits::PalletInfo as PalletInfoTrait, PalletInfo, Runtime,
};

pub mod tokens;
pub mod in_instructions;
pub mod validator_sets;
pub mod dex;

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

impl Serai {
  pub async fn new(url: &str) -> Result<Self, SeraiError> {
    Ok(Serai(OnlineClient::<SeraiConfig>::from_url(url).await.map_err(SeraiError::RpcError)?))
  }

  async fn storage<R: Decode>(
    &self,
    pallet: &'static str,
    name: &'static str,
    keys: Option<Vec<Value>>,
    block: [u8; 32],
  ) -> Result<Option<R>, SeraiError> {
    let storage = self.0.storage();
    let address = subxt::dynamic::storage(pallet, name, keys.unwrap_or(vec![]));
    debug_assert!(storage.validate(&address).is_ok(), "invalid storage address");

    storage
      .at(block.into())
      .fetch(&address)
      .await
      .map_err(SeraiError::RpcError)?
      .map(|res| R::decode(&mut res.encoded()).map_err(|_| SeraiError::InvalidRuntime))
      .transpose()
  }

  async fn events<P: 'static, E: Decode>(
    &self,
    block: [u8; 32],
    filter: impl Fn(&E) -> bool,
  ) -> Result<Vec<E>, SeraiError> {
    let mut res = vec![];
    for event in self.0.events().at(block.into()).await.map_err(SeraiError::RpcError)?.iter() {
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

  pub async fn get_latest_block_hash(&self) -> Result<[u8; 32], SeraiError> {
    Ok(self.0.rpc().finalized_head().await.map_err(SeraiError::RpcError)?.into())
  }

  pub async fn get_latest_block(&self) -> Result<Block, SeraiError> {
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
    let finalized = self.get_latest_block_hash().await?.into();
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

  pub async fn get_block(&self, hash: [u8; 32]) -> Result<Option<Block>, SeraiError> {
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

  // Ideally, this would be get_block_hash, not get_block_by_number
  // Unfortunately, in order to only operate over only finalized data, we have to check the
  // returned hash is for a finalized block. We can only do that by calling the extensive
  // is_finalized method, which at least requires the header
  // In practice, the block is likely more useful than the header
  pub async fn get_block_by_number(&self, number: u64) -> Result<Option<Block>, SeraiError> {
    let Some(hash) =
      self.0.rpc().block_hash(Some(number.into())).await.map_err(SeraiError::RpcError)?
    else {
      return Ok(None);
    };
    self.get_block(hash.into()).await
  }

  pub async fn get_nonce(&self, address: &SeraiAddress) -> Result<u32, SeraiError> {
    self
      .0
      .rpc()
      .system_account_next_index(&sp_core::sr25519::Public(address.0).to_string())
      .await
      .map_err(SeraiError::RpcError)
  }

  fn unsigned<P: 'static, C: Encode>(call: &C) -> Encoded {
    // TODO: Should Serai purge the old transaction code AND set this to 0/1?
    const TRANSACTION_VERSION: u8 = 4;

    // Protocol version
    let mut bytes = vec![TRANSACTION_VERSION];

    // Pallet index
    bytes.push(u8::try_from(PalletInfo::index::<P>().unwrap()).unwrap());
    // Call
    bytes.extend(call.encode());

    // Prefix the length
    let mut complete_bytes = scale::Compact(u32::try_from(bytes.len()).unwrap()).encode();
    complete_bytes.extend(bytes);
    Encoded(complete_bytes)
  }

  pub fn sign<S: Send + Sync + Signer<SeraiConfig>>(
    &self,
    signer: &S,
    payload: &Payload<Composite<()>>,
    nonce: u32,
    params: BaseExtrinsicParamsBuilder<SeraiConfig, Tip>,
  ) -> Result<Encoded, SeraiError> {
    TxClient::new(self.0.offline())
      .create_signed_with_nonce(payload, signer, nonce, params)
      .map(|tx| Encoded(tx.into_encoded()))
      // TODO: Don't have this potentially return an error (requires modifying the Payload type)
      .map_err(|_| SeraiError::InvalidRuntime)
  }

  pub async fn publish(&self, tx: &Encoded) -> Result<(), SeraiError> {
    // Drop the hash, which is the hash of the raw TX, as TXs are allowed to share hashes and this
    // hash is practically useless/unsafe
    // If we are to return something, it should be block included in and position within block
    self.0.rpc().submit_extrinsic(tx).await.map(|_| ()).map_err(SeraiError::RpcError)
  }

  pub async fn get_sri_balance(
    &self,
    block: [u8; 32],
    address: SeraiAddress,
  ) -> Result<u64, SeraiError> {
    let data: Option<
      serai_runtime::system::AccountInfo<u32, serai_runtime::balances::AccountData<u64>>,
    > = self.storage("System", "Account", Some(vec![scale_value(address)]), block).await?;
    Ok(data.map(|data| data.data.free).unwrap_or(0))
  }

  pub fn transfer_sri(to: SeraiAddress, amount: Amount) -> Payload<Composite<()>> {
    Payload::new(
      "Balances",
      // TODO: Use transfer_allow_death?
      // TODO: Replace the Balances pallet with something much simpler
      "transfer",
      scale_composite(serai_runtime::balances::Call::<Runtime>::transfer {
        dest: to,
        value: amount.0,
      }),
    )
  }
}

#[derive(Clone)]
pub struct PairSigner(Pair, <SeraiConfig as SubxtConfig>::AccountId);
impl PairSigner {
  pub fn new(pair: Pair) -> Self {
    let id = pair.public();
    PairSigner(pair, id)
  }
}
impl Signer<SeraiConfig> for PairSigner {
  fn account_id(&self) -> &<SeraiConfig as SubxtConfig>::AccountId {
    &self.1
  }
  fn address(&self) -> <SeraiConfig as SubxtConfig>::Address {
    self.1.into()
  }
  fn sign(&self, payload: &[u8]) -> <SeraiConfig as SubxtConfig>::Signature {
    self.0.sign(payload)
  }
}
