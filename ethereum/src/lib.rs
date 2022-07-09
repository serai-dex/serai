// use web3;
// use web3::contract::{Contract, Options};
// //use web3::types::U256;
// use serde;
// use serde_json;
// use serde_json::Value;
// use std::fs;

pub mod contract; 

// #[derive(serde::Deserialize, serde::Serialize)]
// #[serde(rename_all = "camelCase")]
// pub struct CompiledContract {
//     contract_name: String,
//     bytecode: String,
// }

// pub async fn deploy_contract(
//     from: web3::types::Address,
//     filepath: String,
// ) -> web3::Result<Contract<web3::transports::http::Http>> {
//     let transport = web3::transports::Http::new("http://localhost:8545")?;
//     let web3 = web3::Web3::new(transport);
//     let file_contents = fs::read_to_string(filepath).unwrap();
//     print!("{:?}", file_contents);
//     let compiled_contract: Value = serde_json::from_slice(file_contents.as_bytes()).unwrap(); // TODO: wrap err
//     let bytecode = compiled_contract["bytecode"].as_str().unwrap();
//     let contract = Contract::deploy(web3.eth(), include_bytes!("../schnorr-verify/artifacts/contracts/Schnorr.sol/Schnorr.json")/* file_contents.as_bytes()*/).unwrap()
//     .confirmations(0)
//     .options(Options::with(|opt| {
//         opt.value = Some(5.into());
//         opt.gas_price = Some(5.into());
//         opt.gas = Some(3_000_000.into());
//     }))
//     .execute(
//         bytecode,
//         (),
//         //(U256::from(1_000_000_u64), "My Token".to_owned(), 3u64, "MT".to_owned()),
//         from,
//     )
//     .await.unwrap(); // TODO: wrap err
//     Ok(contract)
// }

// #[cfg(test)]
// mod tests {
//     use crate::deploy_contract;
//     use hex_literal::hex;

//     #[actix_rt::test]
//     async fn test_deploy_contract() {
//         let from = hex!("90F8bf6A479f320ead074411a4B0e7944Ea8c9C1").into();
//         let _contract = deploy_contract(
//             from,
//             "./schnorr-verify/artifacts/contracts/Schnorr.sol/Schnorr.json".to_string(),
//         )
//         .await
//         .unwrap();
//     }
// }
