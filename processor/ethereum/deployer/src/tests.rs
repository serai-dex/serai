use std::sync::Arc;

use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_simple_request_transport::SimpleRequest;
use alloy_rpc_client::ClientBuilder;
use alloy_provider::{Provider as _, RootProvider};

use alloy_node_bindings::Anvil;

use crate::{
  abi::Deployer::{PriorDeployed, DeploymentFailed, DeployerErrors},
  Deployer,
};

#[tokio::test]
async fn test_deployer() {
  const OSAKA: &str = "osaka";
  const LATEST: &str = "latest";

  for network in [OSAKA, LATEST] {
    let anvil = (if network == LATEST {
      // If this is the latest network, it's inherently defaulted to when `anvil` is spawned
      Anvil::new()
    } else {
      // Else, we explicitly specify the hardwork
      Anvil::new().arg("--hardfork").arg(network)
    })
    .spawn();

    let provider = Arc::new(RootProvider::new(
      ClientBuilder::default().transport(SimpleRequest::new(anvil.endpoint()).unwrap(), true),
    ));

    // Deploy the Deployer
    {
      let deployment_tx = Deployer::deployment_tx();
      let gas_programmed = deployment_tx.tx().gas_limit;
      let receipt = ethereum_test_primitives::publish_tx(&provider, deployment_tx).await;
      assert!(receipt.status());
      assert_eq!(receipt.contract_address.unwrap(), Deployer::address());

      if network == OSAKA {
        // Check the gas programmed was twice the gas used
        // We only check this for Osaka as the constant was programmed per Osaka's gas pricing
        assert_eq!(2 * receipt.gas_used, gas_programmed);
      }
    }

    // Deploy the deployer with the deployer
    let mut deploy_tx = Deployer::deploy_tx(crate::INITCODE.to_vec());
    deploy_tx.gas_price = 100_000_000_000u128;
    deploy_tx.gas_limit = 1_000_000;
    {
      let deploy_tx = ethereum_primitives::deterministically_sign(deploy_tx.clone());
      let receipt = ethereum_test_primitives::publish_tx(&provider, deploy_tx).await;
      assert!(receipt.status());
    }

    // Verify we can now find the deployer
    {
      let deployer = Deployer::new(provider.clone()).await.unwrap().unwrap();
      let deployed_deployer = deployer
        .find_deployment(ethereum_primitives::keccak256(crate::INITCODE))
        .await
        .unwrap()
        .unwrap();
      assert_eq!(
        provider.get_code_at(deployed_deployer).await.unwrap(),
        provider.get_code_at(Deployer::address()).await.unwrap(),
      );
      assert!(deployed_deployer != Deployer::address());
    }

    // Verify deploying the same init code multiple times fails
    {
      let mut deploy_tx = deploy_tx;
      // Change the gas price to cause a distinct message, and with it, a distinct signer
      deploy_tx.gas_price += 1;
      let deploy_tx = ethereum_primitives::deterministically_sign(deploy_tx);
      let receipt = ethereum_test_primitives::publish_tx(&provider, deploy_tx.clone()).await;
      assert!(!receipt.status());

      let call = TransactionRequest::default()
        .to(Deployer::address())
        .input(TransactionInput::new(deploy_tx.tx().input.clone()));
      let call_err = provider.call(call).await.unwrap_err();
      assert!(matches!(
        call_err.as_error_resp().unwrap().as_decoded_interface_error::<DeployerErrors>().unwrap(),
        DeployerErrors::PriorDeployed(PriorDeployed {}),
      ));
    }

    // Verify deployment failures yield errors properly
    {
      // 0xfe is an invalid opcode which is guaranteed to remain invalid
      let mut deploy_tx = Deployer::deploy_tx(vec![0xfe]);
      deploy_tx.gas_price = 100_000_000_000u128;
      deploy_tx.gas_limit = 1_000_000;

      let deploy_tx = ethereum_primitives::deterministically_sign(deploy_tx);
      let receipt = ethereum_test_primitives::publish_tx(&provider, deploy_tx.clone()).await;
      assert!(!receipt.status());

      let call = TransactionRequest::default()
        .to(Deployer::address())
        .input(TransactionInput::new(deploy_tx.tx().input.clone()));
      let call_err = provider.call(call).await.unwrap_err();
      assert!(matches!(
        call_err.as_error_resp().unwrap().as_decoded_interface_error::<DeployerErrors>().unwrap(),
        DeployerErrors::DeploymentFailed(DeploymentFailed {}),
      ));
    }
  }
}
