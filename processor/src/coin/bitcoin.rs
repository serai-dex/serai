use std::{str::FromStr};

use async_trait::async_trait;
use curve25519_dalek::scalar::Scalar as OtherScalar;

use dalek_ff_group as dfg;
use transcript::RecommendedTranscript;
use frost::{ curve::Ed25519, ThresholdKeys };

use bitcoin::util::address::Address;
use bitcoin_serai::{rpc::Rpc};
use bitcoincore_rpc_json::{GetBlockResult, AddressType}; //, EstimateSmartFeeResult, ListUnspentResultEntry

use crate::{
  additional_key,
  coin::{CoinError, Output as OutputTrait, Coin},
};

//Todo: Delete it later
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fee {
  pub per_weight: u64,
  pub mask: u64,
}

impl Fee {
  pub fn calculate(&self, weight: usize) -> u64 {
    ((((self.per_weight * u64::try_from(weight).unwrap()) - 1) / self.mask) + 1) * self.mask
  }
}

#[derive(Clone, Debug)]
pub struct Bitcoin {
  pub(crate) rpc: Rpc,
  view: OtherScalar,
}

impl Bitcoin {
  pub async fn new(url: String, username:Option<String>, userpass:Option<String>) -> Bitcoin {
    Bitcoin {
      rpc: Rpc::new(url, username.unwrap(), userpass.unwrap()).unwrap(),
      //Client::new(&url, Auth::UserPass("serai".to_string(), "seraidex".to_string())).unwrap(),
      view: additional_key::<Bitcoin>(0).0,
    }
  }
}

//TODO: Implement proper Structs
pub struct SignableTransaction {}
use monero_serai::{transaction::Transaction,wallet::{SpendableOutput, TransactionMachine}};
#[derive(Clone, Debug)]
pub struct Output(SpendableOutput);
impl From<SpendableOutput> for Output {
  fn from(output: SpendableOutput) -> Output {
    Output(output)
  }
}
impl OutputTrait for Output {
  // While we could use (tx, o), using the key ensures we won't be susceptible to the burning bug.
  // While the Monero library offers a variant which allows senders to ensure their TXs have unique
  // output keys, Serai can still be targeted using the classic burning bug
  type Id = [u8; 32];

  fn id(&self) -> Self::Id {
    self.0.output.data.key.compress().to_bytes()
  }

  fn amount(&self) -> u64 {
    self.0.commitment().amount
  }

  fn serialize(&self) -> Vec<u8> {
    self.0.serialize()
  }

  fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
    SpendableOutput::deserialize(reader).map(Output)
  }
}

#[async_trait]
impl Coin for Bitcoin {
  type Curve = Ed25519;

  type Fee = Fee;
  type Transaction =  Transaction;//bitcoin::Transaction;
  type Block = GetBlockResult; //Block;

  type Output = Output;
  type SignableTransaction = SignableTransaction;
  type TransactionMachine = TransactionMachine;

  type Address = bitcoin::util::address::Address;

  const ID: &'static [u8] = b"Bitcoin";
  const CONFIRMATIONS: usize = 10;

  const MAX_INPUTS: usize = 128;
  const MAX_OUTPUTS: usize = 16;

  fn address(&self, key: dfg::EdwardsPoint) -> Self::Address {
    Self::Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf").unwrap()
  }

  async fn get_latest_block_number(&self) -> Result<usize, CoinError> {
    // - defines height as chain length, so subtract 1 for block number
    let block_result = self.rpc.get_height().await.map_err(|_| CoinError::ConnectionError);
    let block_number = match block_result {
      Ok(val) => Ok(val as usize),
      Err(_) => return Err(CoinError::ConnectionError),
    };

    return block_number;
  }

  async fn get_block(&self, number: usize) -> Result<Self::Block, CoinError> {
    let block_number = number as u64;
    let block_hash = self.rpc.get_block_hash(block_number - 1).await.unwrap();
    let block_hash_str = block_hash.to_string();
    let info = self.rpc.get_block(&block_hash_str.to_string()).await.unwrap();
    Ok(info)
  }

  async fn is_confirmed(&self, tx: &[u8]) -> Result<bool, CoinError> {
    let txid_str = String::from_utf8(tx.to_vec()).unwrap();
    let tx_block_number = self.rpc.get_transaction_block_number(&txid_str.to_string()).await.unwrap();
    Ok((self.get_latest_block_number().await.unwrap().saturating_sub(tx_block_number) + 1) >= 10)
  }

  //TODO: 
  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: dfg::EdwardsPoint,
  ) -> Result<Vec<Self::Output>, CoinError> {
    return Err(CoinError::ConnectionError);
  }

  //TODO: Add sending logic
  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Ed25519>,
    transcript: RecommendedTranscript,
    block_number: usize,
    mut inputs: Vec<Output>,
    payments: &[(Address, u64)],
    fee: Fee,
  ) -> Result<SignableTransaction, CoinError> {
    let spend = keys.group_key();
    return Err(CoinError::ConnectionError);
  }

  //TODO: Add sending logic
  async fn attempt_send(
    &self,
    transaction: SignableTransaction,
    included: &[u16],
  ) -> Result<Self::TransactionMachine, CoinError> {
    return Err(CoinError::ConnectionError);
  }

  //TODO: Add publishing logic
  async fn publish_transaction(
    &self,
    tx: &Self::Transaction,
  ) -> Result<(Vec<u8>, Vec<<Self::Output as OutputTrait>::Id>), CoinError> {
    return Err(CoinError::ConnectionError);
    //self.rpc.publish_transaction(tx).await.map_err(|_| CoinError::ConnectionError)?;

    //Ok((tx.hash().to_vec(), tx.prefix.outputs.iter().map(|output| output.key.to_bytes()).collect()))
  }

  #[cfg(test)]
  async fn get_fee(&self) -> Self::Fee {
    Self::Fee { per_weight: 36, mask: 66 }
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    let address : bitcoin::util::address::Address = self.rpc.get_new_address(None, Some(AddressType::Legacy)).await.unwrap();
    let new_block = self.rpc.generate_to_address(1, address.to_string().as_str()).await.unwrap();
    dbg!(&new_block);
  }

  #[cfg(test)]
  async fn test_send(&self, address: Self::Address) {
    let address_str = String::from("bcrt1q7kc7tm3a4qljpw4gg5w73cgya6g9nfydtessgs");//new_addr.to_string();
    //let result  = btc_rpc.generate_to_address(1, address_str.as_str()).await.unwrap();
    let from_addr = Address::from_str(address_str.as_str()).unwrap();
    let mut utxos = self.rpc.get_spendable(None, None, Some(vec![address_str.as_str()]), None).await.unwrap();

    let mut txin_list_complete = Vec::new();
    let fee = 0.001;
    let send_amount = 153.41521;
    let total_amount = send_amount + fee;

    let mut sum = 0.0;
    let mut diff = 9999999999999.0;
    let mut temp_diff = 0.0;
    let mut utxo_id = 0;
    let mut changed_amount = 0.0;

    let it = utxos.iter();
    for (i, one_utx) in it.enumerate() {
        //dbg!(&one_utx.amount);
        temp_diff = one_utx.amount.to_btc() - total_amount;
        if temp_diff > 0.0 && temp_diff < diff {
            diff = temp_diff;
            utxo_id = i + 1;
        } 
        sum += one_utx.amount.to_btc();
    }

    if total_amount > sum {
        panic!("No way to reach that much of bitcoin to send !");
    }

    if utxo_id == 0 {
        println!("No utxo found - Total : {}",sum);
        utxos.sort_by(|k1:&ListUnspentResultEntry, k2:&ListUnspentResultEntry| {
            k2.amount.cmp(&k1.amount)
        });
        sum = 0.0;
        let it = utxos.iter();
        for (i, one_utx) in it.enumerate() {
            sum += one_utx.amount.to_btc();
            txin_list_complete.push(&utxos[i]);
            if sum > total_amount {
                changed_amount = sum - total_amount;
                break;
            }
        }
        println!("Sum : {}  Target: {}   Changed: {}",sum, total_amount, changed_amount);
    }
    else {
        txin_list_complete.push(&utxos[utxo_id-1]);
    }

    println!("Diff: {}   -  Best ID : {}", diff, utxo_id);
    //dbg!(&txin_list_complete);
    let to_addr_str = "n2eMqTT929pb1RDNuqEnxdaLau1rxy3efi";
    let to_addr = bitcoin::Address::from_str(to_addr_str).unwrap();

    let it = utxos.iter();
    for (i, one_utx) in it.enumerate() {
        //dbg!(&one_utx.amount);
        temp_diff = one_utx.amount.to_btc() - total_amount;
        if temp_diff > 0.0 && temp_diff < diff {
            diff = temp_diff;
            utxo_id = i + 1;
        } 
        sum += one_utx.amount.to_btc();
    }

    if total_amount > sum {
        panic!("No way to reach that much of bitcoin to send !");
    }

    if utxo_id == 0 {
        println!("No utxo found - Total : {}",sum);
        utxos.sort_by(|k1:&ListUnspentResultEntry, k2:&ListUnspentResultEntry| {
            k2.amount.cmp(&k1.amount)
        });
        sum = 0.0;
        let it = utxos.iter();
        for (i, one_utx) in it.enumerate() {
            sum += one_utx.amount.to_btc();
            txin_list_complete.push(&utxos[i]);
            if sum > total_amount {
                changed_amount = sum - total_amount;
                break;
            }
        }
        println!("Sum : {}  Target: {}   Changed: {}",sum, total_amount, changed_amount);
    }
    else {
        txin_list_complete.push(&utxos[utxo_id-1]);
    }

    println!("Diff: {}   -  Best ID : {}", diff, utxo_id);
    //dbg!(&txin_list_complete);
    let to_addr_str = "n2eMqTT929pb1RDNuqEnxdaLau1rxy3efi";
    let to_addr = bitcoin::Address::from_str(to_addr_str).unwrap();

    let mut vin_list = Vec::new();

    for one_txin in txin_list_complete.iter() {
        vin_list.push(
        CreateRawTransactionInput {
            txid: one_txin.txid,
            vout: one_txin.vout,
            sequence: None
        });
    }

    let mut out_scr = HashMap::new();
    out_scr.insert(to_addr.to_string(),bitcoin::Amount::from_btc(send_amount).unwrap());
    if changed_amount > 0.0 {
        //TODO: PRECISE ERROR = 46.58378999999999 example
        out_scr.insert(from_addr.to_string(),bitcoin::Amount::from_btc(changed_amount).unwrap());
    }
    let raw_transaction = btc_rpc.create_raw_transaction(&vin_list, &out_scr, None, None).await.unwrap();
  }
}
