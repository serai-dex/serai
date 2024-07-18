pub(crate) use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpListener,
};

use serai_db::{Get, DbTxn, Db as DbTrait};

#[tokio::main(flavor = "current_thread")]
async fn main() {
  // Override the panic handler with one which will panic if any tokio task panics
  {
    let existing = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
      existing(panic);
      const MSG: &str = "exiting the process due to a task panicking";
      println!("{MSG}");
      log::error!("{MSG}");
      std::process::exit(1);
    }));
  }

  if std::env::var("RUST_LOG").is_err() {
    std::env::set_var("RUST_LOG", serai_env::var("RUST_LOG").unwrap_or_else(|| "info".to_string()));
  }
  env_logger::init();

  log::info!("Starting Ethereum relayer server...");

  // Open the DB
  #[allow(unused_variables, unreachable_code)]
  let db = {
    #[cfg(all(feature = "parity-db", feature = "rocksdb"))]
    panic!("built with parity-db and rocksdb");
    #[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
    let db =
      serai_db::new_parity_db(&serai_env::var("DB_PATH").expect("path to DB wasn't specified"));
    #[cfg(feature = "rocksdb")]
    let db =
      serai_db::new_rocksdb(&serai_env::var("DB_PATH").expect("path to DB wasn't specified"));
    db
  };

  // Start command recipience server
  // This should not be publicly exposed
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
          loop {
            let Ok(msg_len) = socket.read_u32_le().await else { break };
            let mut buf = vec![0; usize::try_from(msg_len).unwrap()];
            let Ok(_) = socket.read_exact(&mut buf).await else { break };

            if buf.len() < 5 {
              break;
            }
            let nonce = u32::from_le_bytes(buf[.. 4].try_into().unwrap());
            let mut txn = db.txn();
            txn.put(nonce.to_le_bytes(), &buf[4 ..]);
            txn.commit();

            let Ok(()) = socket.write_all(&[1]).await else { break };

            log::info!("received signed command #{nonce}");
          }
        });
      }
    }
  });

  // Start command fetch server
  // 5132 ^ ((b'E' << 8) | b'R') + 1
  let server = TcpListener::bind("0.0.0.0:20831").await.unwrap();
  loop {
    let (mut socket, _) = server.accept().await.unwrap();
    let db = db.clone();
    tokio::spawn(async move {
      let db = db.clone();
      loop {
        // Nonce to get the router comamnd for
        let mut buf = vec![0; 4];
        let Ok(_) = socket.read_exact(&mut buf).await else { break };

        let command = db.get(&buf[.. 4]).unwrap_or(vec![]);
        let Ok(()) = socket.write_all(&u32::try_from(command.len()).unwrap().to_le_bytes()).await
        else {
          break;
        };
        let Ok(()) = socket.write_all(&command).await else { break };
      }
    });
  }
}
