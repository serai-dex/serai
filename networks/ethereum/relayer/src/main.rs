pub(crate) use tokio::{
  io::{AsyncReadExt as _, AsyncWriteExt as _},
  net::TcpListener,
};

use serai_db::{Get as _, Transaction as _, Db as _};

use serai_env::Environment;

#[tokio::main(flavor = "current_thread")]
async fn main() {
  serai_env::init_logger();
  serai_env::info!("Starting Ethereum relayer server...");

  // Open the DB
  #[expect(unused_variables, unreachable_code)]
  let db = {
    #[cfg(all(feature = "parity-db", feature = "rocksdb"))]
    panic!("built with parity-db and rocksdb");

    let env = Environment::from_secret_store().await;

    #[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
    let db = serai_db::new_parity_db(env.var("DB_PATH").expect("path to DB wasn't specified"));
    #[cfg(feature = "rocksdb")]
    let db = serai_db::new_rocksdb(env.var("DB_PATH").expect("path to DB wasn't specified"));
    db
  };

  // Start transaction recipience server
  // This MUST NOT be publicly exposed
  // TODO: Add auth
  tokio::spawn({
    let db = db.clone();
    async move {
      // 5132 ^ ((b'E' << 8) | b'R')
      let server = TcpListener::bind("0.0.0.0:20830").await.unwrap();
      loop {
        let (mut socket, _) = server.accept().await.unwrap();
        let db = db.clone();
        tokio::spawn(async move {
          let mut db = db.clone();
          while let Ok(msg_len) = socket.read_u32_le().await {
            let mut buf = vec![0; usize::try_from(msg_len).unwrap()];
            let Ok(_) = socket.read_exact(&mut buf).await else { break };

            if buf.len() < (4 + 1) {
              break;
            }
            let nonce = u32::from_le_bytes(buf[.. 4].try_into().unwrap());
            let mut txn = db.txn();
            // Save the transaction
            txn.set(nonce.to_le_bytes(), &buf[4 ..]);
            txn.commit();

            let Ok(()) = socket.write_all(&[1]).await else { break };

            serai_env::info!("received transaction to publish (nonce {nonce})");
          }
        });
      }
    }
  });

  // Start transaction fetch server
  // 5132 ^ ((b'E' << 8) | b'R') + 1
  // TODO: JSON-RPC server which returns this as JSON?
  let server = TcpListener::bind("0.0.0.0:20831").await.unwrap();
  loop {
    let (mut socket, _) = server.accept().await.unwrap();
    let db = db.clone();
    tokio::spawn(async move {
      let db = db.clone();
      loop {
        // Nonce to get the unsigned transaction for
        let mut buf = vec![0; 4];
        let Ok(_) = socket.read_exact(&mut buf).await else { break };

        let transaction = db.get(&buf[.. 4]);
        let transaction = transaction.as_ref().map(AsRef::as_ref).unwrap_or(&[]);
        let Ok(()) =
          socket.write_all(&u32::try_from(transaction.len()).unwrap().to_le_bytes()).await
        else {
          break;
        };
        let Ok(()) = socket.write_all(transaction).await else { break };
      }
    });
  }
}
