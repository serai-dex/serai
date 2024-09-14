use core::future::Future;

use crate::transaction::Transaction;

#[derive(Clone)]
pub(crate) struct TransactionPublisher {
  relayer_url: String,
}

impl TransactionPublisher {
  pub(crate) fn new(relayer_url: String) -> Self {
    Self { relayer_url }
  }
}

impl signers::TransactionPublisher<Transaction> for TransactionPublisher {
  type EphemeralError = ();

  fn publish(
    &self,
    tx: Transaction,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>> {
    async move {
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
