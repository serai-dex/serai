use ethers::{contract::ContractFactory, prelude::*, utils::Anvil};
use eyre::Result;
use std::fs::File;
use std::{convert::TryFrom, sync::Arc, time::Duration};

abigen!(
    Schnorr,
    "./schnorr-verify/artifacts/contracts/Schnorr.sol/Schnorr.json",
    event_derives(serde::Deserialize, serde::Serialize),
);

pub async fn deploy_schnorr_verifier_contract(
) -> Result<schnorr_mod::Schnorr<SignerMiddleware<Provider<Http>, LocalWallet>>> {
    let anvil = Anvil::new().spawn();
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    let provider =
        Provider::<Http>::try_from(anvil.endpoint())?.interval(Duration::from_millis(10u64));
    let client = Arc::new(SignerMiddleware::new(provider, wallet));
    let path = "./schnorr-verify/artifacts/contracts/Schnorr.sol/Schnorr.json";
    let artifact: HardhatArtifact = serde_json::from_reader(File::open(path).unwrap()).unwrap();
    let (abi, bin, _) = artifact.into_parts();
    let factory = ContractFactory::new(abi.unwrap(), bin.unwrap(), client.clone());
    let contract = factory.deploy(())?.send().await?;

    let contract = Schnorr::new(contract.address(), client);
    Ok(contract)
}

#[cfg(test)]
mod tests {
    use super::deploy_schnorr_verifier_contract;

    #[tokio::test]
    async fn test_deploy_contract() {
        let _contract = deploy_schnorr_verifier_contract().await.unwrap();
    }
}
