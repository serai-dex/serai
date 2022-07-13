use ethers::{contract::ContractFactory, prelude::*};
use eyre::{eyre, Result};
use serai_processor::coin::ethereum;
use std::fs::File;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EthereumError {
    #[error("failed to verify Schnorr signature")]
    VerificationError,
}

abigen!(
    Schnorr,
    "./schnorr-verify/artifacts/contracts/Schnorr.sol/Schnorr.json",
    event_derives(serde::Deserialize, serde::Serialize),
);

pub async fn deploy_schnorr_verifier_contract(
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<schnorr_mod::Schnorr<SignerMiddleware<Provider<Http>, LocalWallet>>> {
    let path = "./schnorr-verify/artifacts/contracts/Schnorr.sol/Schnorr.json";
    let artifact: HardhatArtifact = serde_json::from_reader(File::open(path).unwrap()).unwrap();
    let (abi, bin, _) = artifact.into_parts();
    let factory = ContractFactory::new(abi.unwrap(), bin.unwrap(), client.clone());
    let contract = factory.deploy(())?.send().await?;
    let contract = Schnorr::new(contract.address(), client);
    Ok(contract)
}

pub async fn call_verify(
    contract: schnorr_mod::Schnorr<SignerMiddleware<Provider<Http>, LocalWallet>>,
    params: ethereum::ProcessedSignature,
) -> Result<()> {
    let ok = contract
        .verify(
            params.sr.to_bytes().into(),
            params.er.to_bytes().into(),
            params.px.to_bytes().into(),
            params.parity + 27,
            params.message.into(),
            params.e.to_bytes().into(),
        )
        .call()
        .await?;
    if ok {
        Ok(())
    } else {
        Err(eyre!(EthereumError::VerificationError))
    }
}

#[cfg(test)]
mod tests {
    use super::{call_verify, deploy_schnorr_verifier_contract};
    use ethers::{prelude::*, utils::Anvil};
    use std::{convert::TryFrom, sync::Arc, time::Duration};

    #[tokio::test]
    async fn test_deploy_contract() {
        let anvil = Anvil::new().spawn();
        let wallet: LocalWallet = anvil.keys()[0].clone().into();
        let provider = Provider::<Http>::try_from(anvil.endpoint())
            .unwrap()
            .interval(Duration::from_millis(10u64));
        let client = Arc::new(SignerMiddleware::new(provider, wallet));

        let _contract = deploy_schnorr_verifier_contract(client).await.unwrap();
    }

    #[tokio::test]
    async fn test_ecrecover_hack() {
        use ethers::utils::keccak256;
        use frost::{
            algorithm::Schnorr,
            curve::Secp256k1,
            tests::{algorithm_machines, key_gen, sign},
        };
        use k256::elliptic_curve::bigint::ArrayEncoding;
        use k256::{Scalar, U256};
        use rand::rngs::OsRng;
        use serai_processor::coin::ethereum;

        let anvil = Anvil::new().spawn();
        let wallet: LocalWallet = anvil.keys()[0].clone().into();
        let provider = Provider::<Http>::try_from(anvil.endpoint())
            .unwrap()
            .interval(Duration::from_millis(10u64));
        let chain_id = provider.get_chainid().await.unwrap();
        let client = Arc::new(SignerMiddleware::new(provider, wallet));

        let keys = key_gen::<_, Secp256k1>(&mut OsRng);
        let group_key = keys[&1].group_key();

        const MESSAGE: &'static [u8] = b"Hello, World!";
        let hashed_message = keccak256(MESSAGE);
        let chain_id = U256::from(Scalar::from(chain_id.as_u32()));

        let full_message = &[chain_id.to_be_byte_array().as_slice(), &hashed_message].concat();

        let sig = sign(
            &mut OsRng,
            algorithm_machines(
                &mut OsRng,
                Schnorr::<Secp256k1, ethereum::EthereumHram>::new(),
                &keys,
            ),
            full_message,
        );
        let processed_sig = ethereum::preprocess_signature_for_contract(
            hashed_message,
            &sig.R,
            sig.s,
            &group_key,
            chain_id,
        );

        let contract = deploy_schnorr_verifier_contract(client).await.unwrap();
        call_verify(contract, processed_sig).await.unwrap();
    }
}
