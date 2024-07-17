use crate::Network;

pub fn anvil(network: Network) -> (String, String, String) {
  assert_eq!(network, Network::Dev);

  const ANVIL_SETUP: &str = r#"
RUN curl -L https://foundry.paradigm.xyz | bash || exit 0
RUN ~/.foundry/bin/foundryup

EXPOSE 8545
"#;

  (String::new(), "RUN apt install git curl -y".to_string(), ANVIL_SETUP.to_string())
}
