use std::sync::Arc;

use async_trait::async_trait;

use curve25519_dalek::scalar::Scalar;

use dalek_ff_group as dfg;
use frost::{curve::Ed25519, FrostKeys};
use transcript::RecommendedTranscript;

use monero_serai::{
    rpc::Rpc,
    transaction::Transaction,
    wallet::{
        address::{Address, AddressType, Network},
        Fee, SignableTransaction as MSignableTransaction, SpendableOutput, TransactionMachine,
        ViewPair,
    },
};

use crate::{
    coin::{Coin, CoinError, Output as OutputTrait},
    view_key,
};

#[derive(Clone, Debug)]
pub struct Output(SpendableOutput);
impl OutputTrait for Output {
    // While we could use (tx, o), using the key ensures we won't be susceptible to the burning bug.
    // While the Monero library offers a variant which allows senders to ensure their TXs have unique
    // output keys, Serai can still be targeted using the classic burning bug
    type Id = [u8; 32];

    fn id(&self) -> Self::Id {
        self.0.key.compress().to_bytes()
    }

    fn amount(&self) -> u64 {
        self.0.commitment.amount
    }

    fn serialize(&self) -> Vec<u8> {
        self.0.serialize()
    }

    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        SpendableOutput::deserialize(reader).map(|o| Output(o))
    }
}

impl From<SpendableOutput> for Output {
    fn from(output: SpendableOutput) -> Output {
        Output(output)
    }
}

#[derive(Debug)]
pub struct SignableTransaction(
    Arc<FrostKeys<Ed25519>>,
    RecommendedTranscript,
    usize,
    MSignableTransaction,
);

#[derive(Clone, Debug)]
pub struct Monero {
    pub(crate) rpc: Rpc,
    view: Scalar,
}

impl Monero {
    pub fn new(url: String) -> Monero {
        let view = view_key::<Monero>(0).0;
        Monero {
            rpc: Rpc::new(url),
            view,
        }
    }

    fn view_pair(&self, spend: dfg::EdwardsPoint) -> ViewPair {
        ViewPair {
            spend: spend.0,
            view: self.view,
        }
    }

    #[cfg(test)]
    fn empty_view_pair(&self) -> ViewPair {
        use group::Group;
        self.view_pair(dfg::EdwardsPoint::generator())
    }

    #[cfg(test)]
    fn empty_address(&self) -> Address {
        self.empty_view_pair()
            .address(Network::Mainnet, AddressType::Standard, false)
    }
}

#[async_trait]
impl Coin for Monero {
    type Curve = Ed25519;

    type Fee = Fee;
    type Transaction = Transaction;
    type Block = Vec<Transaction>;

    type Output = Output;
    type SignableTransaction = SignableTransaction;
    type TransactionMachine = TransactionMachine;

    type Address = Address;

    const ID: &'static [u8] = b"Monero";
    const CONFIRMATIONS: usize = 10;
    // Testnet TX bb4d188a4c571f2f0de70dca9d475abc19078c10ffa8def26dd4f63ce1bcfd79 uses 146 inputs
    // while using less than 100kb of space, albeit with just 2 outputs (though outputs share a BP)
    // The TX size limit is half the contextual median block weight, where said weight is >= 300,000
    // This means any TX which fits into 150kb will be accepted by Monero
    // 128, even with 16 outputs, should fit into 100kb. Further efficiency by 192 may be viable
    // TODO: Get hard numbers and tune
    const MAX_INPUTS: usize = 128;
    const MAX_OUTPUTS: usize = 16;

    fn address(&self, key: dfg::EdwardsPoint) -> Self::Address {
        self.view_pair(key)
            .address(Network::Mainnet, AddressType::Standard, true)
    }

    async fn get_height(&self) -> Result<usize, CoinError> {
        self.rpc
            .get_height()
            .await
            .map_err(|_| CoinError::ConnectionError)
    }

    async fn get_block(&self, height: usize) -> Result<Self::Block, CoinError> {
        self.rpc
            .get_block_transactions_possible(height)
            .await
            .map_err(|_| CoinError::ConnectionError)
    }

    async fn get_outputs(&self, block: &Self::Block, key: dfg::EdwardsPoint) -> Vec<Self::Output> {
        block
            .iter()
            .flat_map(|tx| tx.scan(self.view_pair(key), true).not_locked())
            .map(Output::from)
            .collect()
    }

    async fn prepare_send(
        &self,
        keys: Arc<FrostKeys<Ed25519>>,
        transcript: RecommendedTranscript,
        height: usize,
        mut inputs: Vec<Output>,
        payments: &[(Address, u64)],
        fee: Fee,
    ) -> Result<SignableTransaction, CoinError> {
        let spend = keys.group_key();
        Ok(SignableTransaction(
            keys,
            transcript,
            height,
            MSignableTransaction::new(
                inputs.drain(..).map(|input| input.0).collect(),
                payments.to_vec(),
                Some(self.address(spend)),
                fee,
            )
            .map_err(|_| CoinError::ConnectionError)?,
        ))
    }

    async fn attempt_send(
        &self,
        transaction: SignableTransaction,
        included: &[u16],
    ) -> Result<Self::TransactionMachine, CoinError> {
        transaction
            .3
            .clone()
            .multisig(
                &self.rpc,
                (*transaction.0).clone(),
                transaction.1.clone(),
                transaction.2,
                included.to_vec(),
            )
            .await
            .map_err(|_| CoinError::ConnectionError)
    }

    async fn publish_transaction(
        &self,
        tx: &Self::Transaction,
    ) -> Result<(Vec<u8>, Vec<<Self::Output as OutputTrait>::Id>), CoinError> {
        self.rpc
            .publish_transaction(&tx)
            .await
            .map_err(|_| CoinError::ConnectionError)?;

        Ok((
            tx.hash().to_vec(),
            tx.prefix
                .outputs
                .iter()
                .map(|output| output.key.compress().to_bytes())
                .collect(),
        ))
    }

    #[cfg(test)]
    async fn mine_block(&self) {
        #[derive(serde::Deserialize, Debug)]
        struct EmptyResponse {}
        let _: EmptyResponse = self
            .rpc
            .rpc_call(
                "json_rpc",
                Some(serde_json::json!({
                  "method": "generateblocks",
                  "params": {
                    "wallet_address": self.empty_address().to_string(),
                    "amount_of_blocks": 10
                  },
                })),
            )
            .await
            .unwrap();
    }

    #[cfg(test)]
    async fn test_send(&self, address: Self::Address) {
        use rand::rngs::OsRng;

        let height = self.get_height().await.unwrap();

        self.mine_block().await;
        for _ in 0..7 {
            self.mine_block().await;
        }

        let outputs = self
            .rpc
            .get_block_transactions_possible(height)
            .await
            .unwrap()
            .swap_remove(0)
            .scan(self.empty_view_pair(), false)
            .ignore_timelock();

        let amount = outputs[0].commitment.amount;
        let fee = 1000000000; // TODO
        let tx = MSignableTransaction::new(
            outputs,
            vec![(address, amount - fee)],
            Some(self.empty_address()),
            self.rpc.get_fee().await.unwrap(),
        )
        .unwrap()
        .sign(&mut OsRng, &self.rpc, &Scalar::one())
        .await
        .unwrap();
        self.rpc.publish_transaction(&tx).await.unwrap();
        self.mine_block().await;
    }
}
