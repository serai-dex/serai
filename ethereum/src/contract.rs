use ethers::{prelude::*, utils::Anvil};
use eyre::Result;
use std::{convert::TryFrom, sync::Arc, time::Duration};

abigen!(Schnorr, "./schnorr-verify/artifacts/contracts/Schnorr.sol/Schnorr.json",);

async fn deploy_contract() -> Result<Contract> {
    // 1. compile the contract (note this requires that you are inside the `examples` directory) and
    // launch anvil
    let anvil = Anvil::new().spawn();

    // 2. instantiate our wallet
    let wallet: LocalWallet = anvil.keys()[0].clone().into();

    // 3. connect to the network
    let provider =
        Provider::<Http>::try_from(anvil.endpoint())?.interval(Duration::from_millis(10u64));

    // 4. instantiate the client with the wallet
    let client = Arc::new(SignerMiddleware::new(provider, wallet));

    // 5. deploy contract
    let contract =
        Schnrr::deploy(client).unwrap().send().await.unwrap();

    // 6. call contract function
    let greeting = greeter_contract.greet().call().await.unwrap();
    assert_eq!("Hello World!", greeting);

    Ok(contract)
}

#[cfg(test)]
mod tests {
    use crate::deploy_contract;
    // use hex_literal::hex;

    #[actix_rt::test]
    async fn test_deploy_contract() {
        let _contract = deploy_contract().unwrap();
    }
}