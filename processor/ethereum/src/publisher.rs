use core::future::Future;
use std::sync::Arc;

use alloy_rlp::Encodable;

use alloy_transport::{TransportErrorKind, RpcError};
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::RootProvider;

use tokio::{
  sync::{RwLockReadGuard, RwLock},
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpStream,
};

use serai_db::Db;

use ethereum_schnorr::PublicKey;
use ethereum_router::{OutInstructions, Router};

use crate::{
  InitialSeraiKey,
  transaction::{Action, Transaction},
};

#[derive(Clone)]
pub(crate) struct TransactionPublisher<D: Db> {
  db: D,
  rpc: Arc<RootProvider<SimpleRequest>>,
  router: Arc<RwLock<Option<Router>>>,
  relayer_url: String,
}

impl<D: Db> TransactionPublisher<D> {
  pub(crate) fn new(db: D, rpc: Arc<RootProvider<SimpleRequest>>, relayer_url: String) -> Self {
    Self { db, rpc, router: Arc::new(RwLock::new(None)), relayer_url }
  }

  // This will always return Ok(Some(_)) or Err(_), never Ok(None)
  async fn router(
    &self,
  ) -> Result<RwLockReadGuard<'_, Option<Router>>, RpcError<TransportErrorKind>> {
    let router = self.router.read().await;

    // If the router is None, find it on-chain
    if router.is_none() {
      drop(router);
      let mut router = self.router.write().await;
      // Check again if it's None in case a different task already did this
      if router.is_none() {
        let Some(router_actual) = Router::new(
          self.rpc.clone(),
          &PublicKey::new(
            InitialSeraiKey::get(&self.db)
              .expect("publishing a transaction yet never confirmed a key")
              .0,
          )
          .expect("initial key used by Serai wasn't representable on Ethereum"),
        )
        .await?
        else {
          Err(TransportErrorKind::Custom(
            "publishing transaction yet couldn't find router on chain. was our node reset?"
              .to_string()
              .into(),
          ))?
        };
        *router = Some(router_actual);
      }
      return Ok(router.downgrade());
    }

    Ok(router)
  }
}

impl<D: Db> signers::TransactionPublisher<Transaction> for TransactionPublisher<D> {
  type EphemeralError = RpcError<TransportErrorKind>;

  fn publish(
    &self,
    tx: Transaction,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>> {
    async move {
      let router = self.router().await?;
      let router = router.as_ref().unwrap();

      let nonce = tx.0.nonce();
      // Convert from an Action (an internal representation of a signable event) to a TxLegacy
      let tx = match tx.0 {
        Action::SetKey { chain_id: _, nonce: _, key } => router.update_serai_key(&key, &tx.1),
        Action::Batch { chain_id: _, nonce: _, coin, fee, outs } => {
          router.execute(coin, fee, OutInstructions::from(outs.as_ref()), &tx.1)
        }
      };

      // Nonce
      let mut msg = nonce.to_le_bytes().to_vec();
      // Transaction
      tx.encode(&mut msg);

      let Ok(mut socket) = TcpStream::connect(&self.relayer_url).await else {
        Err(TransportErrorKind::Custom(
          "couldn't connect to the relayer server".to_string().into(),
        ))?
      };
      let Ok(()) = socket.write_all(&u32::try_from(msg.len()).unwrap().to_le_bytes()).await else {
        Err(TransportErrorKind::Custom(
          "couldn't send the message's len to the relayer server".to_string().into(),
        ))?
      };
      let Ok(()) = socket.write_all(&msg).await else {
        Err(TransportErrorKind::Custom(
          "couldn't write the message to the relayer server".to_string().into(),
        ))?
      };
      if socket.read_u8().await.ok() != Some(1) {
        Err(TransportErrorKind::Custom(
          "didn't get the ack from the relayer server".to_string().into(),
        ))?;
      }

      Ok(())
    }
  }
}
