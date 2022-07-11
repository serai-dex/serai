use ethers::{contract::ContractFactory, prelude::*, utils::Anvil};
use eyre::{eyre, Result};
use serai_processor::coin::ethereum;
use std::fs::File;
use std::{convert::TryFrom, sync::Arc, time::Duration};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EthereumError {
    #[error("failed to call schnorr.verify")]
    CallError,
}

abigen!(
    Schnorr,
    "./schnorr-verify/artifacts/contracts/Schnorr.sol/Schnorr.json",
    event_derives(serde::Deserialize, serde::Serialize),
);

pub async fn deploy_schnorr_verifier_contract(
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<schnorr_mod::Schnorr<SignerMiddleware<Provider<Http>, LocalWallet>>> {
    // let anvil = Anvil::new().spawn();
    // let wallet: LocalWallet = anvil.keys()[0].clone().into();
    // let provider =
    //     Provider::<Http>::try_from(anvil.endpoint())?.interval(Duration::from_millis(10u64));
    // let client = Arc::new(SignerMiddleware::new(provider, wallet));
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
            params.parity,
            params.message.into(),
            params.e.to_bytes().into(),
        )
        .call()
        .await?;
    if ok {
        Ok(())
    } else {
        Err(eyre!(EthereumError::CallError))
    }
}

#[cfg(test)]
mod tests {
    use super::{call_verify, deploy_schnorr_verifier_contract, schnorr_mod};
    use ethers::{contract::ContractFactory, prelude::*, utils::Anvil};
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
            algorithm::Hram,
            algorithm::Schnorr,
            curve::Secp256k1,
            tests::{algorithm_machines, key_gen, sign},
        };
        use k256::elliptic_curve::bigint::ArrayEncoding;
        use k256::{Scalar, U256};
        use rand::rngs::OsRng;
        use serai_processor::coin::ethereum;

        let keys = key_gen::<_, Secp256k1>(&mut OsRng);
        let group_key = keys[&1].group_key();
        //let group_key_encoded = group_key.to_encoded_point(true);
        //let group_key_compressed = group_key_encoded.as_ref();
        //let group_key_x = Scalar::from_uint_reduced(U256::from_be_slice(&group_key_compressed[1..33]));

        const MESSAGE: &'static [u8] = b"Hello, World!";
        let hashed_message = keccak256(MESSAGE);
        let chain_id = U256::from(Scalar::ONE);

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
        // let q = ecrecover(sr, group_key_compressed[0] - 2, group_key_x, er).unwrap();
        // assert_eq!(q, address(&sig.R));

        let anvil = Anvil::new().spawn();
        let wallet: LocalWallet = anvil.keys()[0].clone().into();
        let provider = Provider::<Http>::try_from(anvil.endpoint())
            .unwrap()
            .interval(Duration::from_millis(10u64));
        let client = Arc::new(SignerMiddleware::new(provider, wallet));

        let contract = deploy_schnorr_verifier_contract(client).await.unwrap();
        call_verify(contract, processed_sig).await.unwrap();
    }
}
