use core::future::Future;
use std::sync::Arc;

use alloy_transport::{TransportErrorKind, RpcError};
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::RootProvider;

use tokio::sync::{RwLockReadGuard, RwLock};

use ethereum_schnorr::PublicKey;
use ethereum_router::{OutInstructions, Router};

use crate::transaction::{Action, Transaction};

#[derive(Clone)]
pub(crate) struct TransactionPublisher {
  initial_serai_key: PublicKey,
  rpc: Arc<RootProvider<SimpleRequest>>,
  router: Arc<RwLock<Option<Router>>>,
  relayer_url: String,
}

impl TransactionPublisher {
  pub(crate) fn new(rpc: Arc<RootProvider<SimpleRequest>>, relayer_url: String) -> Self {
    Self { initial_serai_key: todo!("TODO"), rpc, router: Arc::new(RwLock::new(None)), relayer_url }
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
        let Some(router_actual) = Router::new(self.rpc.clone(), &self.initial_serai_key).await?
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

impl signers::TransactionPublisher<Transaction> for TransactionPublisher {
  type EphemeralError = RpcError<TransportErrorKind>;

  fn publish(
    &self,
    tx: Transaction,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>> {
    async move {
      // Convert from an Action (an internal representation of a signable event) to a TxLegacy
      let router = self.router().await?;
      let router = router.as_ref().unwrap();
      let tx = match tx.0 {
        Action::SetKey { chain_id: _, nonce: _, key } => router.update_serai_key(&key, &tx.1),
        Action::Batch { chain_id: _, nonce: _, outs } => {
          router.execute(OutInstructions::from(outs.as_ref()), &tx.1)
        }
      };

      /*
      use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
      };

      let mut msg = vec![];
      match completion.command() {
        RouterCommand::UpdateSeraiKey { nonce, .. } | RouterCommand::Execute { nonce, .. } => {
          msg.extend(&u32::try_from(nonce).unwrap().to_le_bytes());
        }
      }
      completion.write(&mut msg).unwrap();

      let Ok(mut socket) = TcpStream::connect(&self.relayer_url).await else {
        log::warn!("couldn't connect to the relayer server");
        Err(NetworkError::ConnectionError)?
      };
      let Ok(()) = socket.write_all(&u32::try_from(msg.len()).unwrap().to_le_bytes()).await else {
        log::warn!("couldn't send the message's len to the relayer server");
        Err(NetworkError::ConnectionError)?
      };
      let Ok(()) = socket.write_all(&msg).await else {
        log::warn!("couldn't write the message to the relayer server");
        Err(NetworkError::ConnectionError)?
      };
      if socket.read_u8().await.ok() != Some(1) {
        log::warn!("didn't get the ack from the relayer server");
        Err(NetworkError::ConnectionError)?;
      }

      Ok(())
      */
      todo!("TODO")
    }
  }
}
