use std::{str::FromStr};

use async_trait::async_trait;

use transcript::RecommendedTranscript;
use frost::{ curve::Secp256k1, ThresholdKeys };

use bitcoin_hashes::hex::ToHex;
use bitcoin::{util::address::Address, Txid};
use bitcoin_serai::{rpc::Rpc,rpc_helper::RawTx};
use bitcoincore_rpc_json::{AddressType, GetBlockResult, 
  EstimateSmartFeeResult, CreateRawTransactionInput, 
  SignRawTransactionInput, ListUnspentResultEntry};

use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint,};

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
}

impl Bitcoin {
  pub async fn new(url: String, username:Option<String>, userpass:Option<String>) -> Bitcoin {
    Bitcoin {
      rpc: Rpc::new(url, username.unwrap(), userpass.unwrap()).unwrap(),
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
  type Curve = Secp256k1;

  type Fee = Fee;
  type Transaction =  Transaction;//bitcoin::Transaction;
  type Block = bitcoin::Block;

  type Output = Output;
  type SignableTransaction = SignableTransaction;
  type TransactionMachine = TransactionMachine;

  type Address = bitcoin::util::address::Address;

  const ID: &'static [u8] = b"Bitcoin";
  const CONFIRMATIONS: usize = 10;

  const MAX_INPUTS: usize = 128;
  const MAX_OUTPUTS: usize = 16;

  fn address(&self, key: ProjectivePoint) -> Self::Address {
    let pubkey = bitcoin::util::key::PublicKey::from_slice(key.to_encoded_point(true).as_bytes()).unwrap();
    Address::p2wpkh(&pubkey, bitcoin::network::constants::Network::Regtest).unwrap()
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
    let block_hash = self.rpc.get_block_hash(number - 1).await.unwrap();
    let info = self.rpc.get_block(&block_hash).await.unwrap();
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
    key: ProjectivePoint,
  ) -> Result<Vec<Self::Output>, CoinError> {
    let main_addr = self.address(key);
    dbg!(&main_addr);
    let block_details = self.rpc.get_block_with_transactions(&block.block_hash()).await.unwrap();
    dbg!(&main_addr.script_pubkey());
    for one_transaction in block_details.tx {
      let mut vout = 0;
      for output_tx in one_transaction.vout {
        dbg!(&output_tx);

        let pub_script = main_addr.script_pubkey().asm();
        let pubkey = pub_script.split_whitespace().last().unwrap();

        if output_tx.script_pub_key.asm.contains(pubkey)  {
          
          println!("Here : n: {} , value: {}", output_tx.n, output_tx.value);
        }
        vout += 1;
      }

    }
    return Err(CoinError::ConnectionError);
  }

  //TODO: Add sending logic
  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Secp256k1>,
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
    let new_addr = self.rpc.get_new_address(None, Some(AddressType::Bech32)).await.unwrap();
    self.rpc.generate_to_address(1, new_addr.to_string().as_str()).await.unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, address: Self::Address) {
    dbg!(&address);
    let from_addr = &address;//Address::from_str(String::from("tb1p84x2ryuyfevgnlpnxt9f39gm7r68gwtvllxqe5w2n5ru00s9aquslzggwq").as_str()).unwrap();
    let mut utxos = self.rpc.get_spendable(None, None, Some(vec![from_addr.to_string().as_str()]), None).await.unwrap();
    dbg!(&utxos);
    let mut txin_list_complete = Vec::new();
    
    let fee_amount_sat = bitcoin::Amount::from_sat(100000);
    let send_amount_sat = bitcoin::Amount::from_sat(15341521000);
    let total_amount_sat = fee_amount_sat.checked_add(send_amount_sat).unwrap();

    let mut sum_sat = bitcoin::Amount::from_sat(0);
    let mut diff_sat = bitcoin::Amount::from_sat(9999999999999);
    let mut temp_diff_sat = bitcoin::Amount::from_sat(0);
    let mut utxo_id:usize = 0;
    let mut changed_amount_sat = bitcoin::Amount::from_sat(0);

    let it = utxos.iter();
    for (i, one_utx) in it.enumerate() {
        if one_utx.amount.checked_sub(total_amount_sat).is_some() {
            temp_diff_sat = one_utx.amount.checked_sub(total_amount_sat).unwrap();
            if temp_diff_sat < diff_sat {
                diff_sat = temp_diff_sat;
                utxo_id = i + 1;

                changed_amount_sat = temp_diff_sat;
            } 
        }
        
        sum_sat = sum_sat.checked_add(one_utx.amount).unwrap();
    }

    if total_amount_sat > sum_sat {
        panic!("No way to reach that much of bitcoin to send !");
    }

    if utxo_id == 0 {
        println!("No utxo found - Total : {}",sum_sat.to_sat());
        utxos.sort_by(|k1:&ListUnspentResultEntry, k2:&ListUnspentResultEntry| {
            k2.amount.cmp(&k1.amount)
        });
        sum_sat = bitcoin::Amount::from_sat(0);
        let it = utxos.iter();
        for (i, one_utx) in it.enumerate() {
            sum_sat = sum_sat.checked_add(one_utx.amount).unwrap();
            txin_list_complete.push(&utxos[i]);
            if sum_sat > total_amount_sat {
                changed_amount_sat = sum_sat.checked_sub(total_amount_sat).unwrap();
                break;
            }
        }
        println!("Sum : {}  Target: {}   Changed: {}",sum_sat.to_sat(), total_amount_sat.to_sat(), changed_amount_sat.to_sat());
    }
    else {
        txin_list_complete.push(&utxos[utxo_id-1]);
    }

    println!("Diff: {}   -  Best ID : {}", diff_sat.to_sat(), utxo_id);
    //dbg!(&txin_list_complete);
    /*let to_addr_str = "2N5ZRwT42rHFjAtizZPa3Rp7Tn88PcoSzEB";//"n2eMqTT929pb1RDNuqEnxdaLau1rxy3efi";
    let to_addr = bitcoin::Address::from_str(to_addr_str).unwrap();
    dbg!("Adress Type: {:?}",to_addr.address_type());

    let mut vin_list = Vec::new();

    for one_txin in txin_list_complete.iter() {
        dbg!(&one_txin.amount.to_btc());
        vin_list.push(
        CreateRawTransactionInput {
            txid: one_txin.txid,
            vout: one_txin.vout,
            sequence: None
        });
    }

    let mut out_scr = HashMap::new();
    out_scr.insert(to_addr.to_string(),send_amount_sat);
    if changed_amount_sat.to_sat() > 0 {
        out_scr.insert(from_addr.to_string(),changed_amount_sat);
    }

    let raw_transaction = self.rpc.create_raw_transaction(&vin_list, &out_scr, None, None).await.unwrap();
    dbg!(raw_transaction.raw_hex());

    let priv_keys = vec![privkey_obj];
    let sign_transaction: SignRawTransactionResult = self.rpc.sign_raw_transaction_with_key(raw_transaction.raw_hex(), &priv_keys, None, None).await.unwrap();
    dbg!(hex::encode(&sign_transaction.hex).to_string());
    
    
    let tr_sign_transaction = sign_transaction.transaction().unwrap();
    //dbg!(&tr_sign_transaction.raw_hex());
    let s_raw_transaction = self.rpc.send_raw_transaction(&tr_sign_transaction).await.unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {err}");
        bitcoin::Txid::from_str("849b2bb48eed534bd073c32cc9efa98c5ffa48738c75641f3cef340fd859e112").unwrap()
    });*/

  }
}
