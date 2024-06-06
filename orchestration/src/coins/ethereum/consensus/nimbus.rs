use crate::Network;

pub fn nimbus(network: Network) -> (String, String, String) {
  assert_ne!(network, Network::Dev);

  let platform = match std::env::consts::ARCH {
    "x86_64" => "amd64",
    "arm" => "arm32v7",
    "aarch64" => "arm64v8",
    _ => panic!("unsupported platform"),
  };

  #[rustfmt::skip]
  let checksum = match platform {
    "amd64" => "5da10222cfb555ce2e3820ece12e8e30318945e3ed4b2b88d295963c879daeee071623c47926f880f3db89ce537fd47c6b26fe37e47aafbae3222b58bcec2fba",
    "arm32v7" => "7055da77bfa1186ee2e7ce2a48b923d45ccb039592f529c58d93d55a62bca46566ada451bd7497c3ae691260544f0faf303602afd85ccc18388fdfdac0bb2b45",
    "arm64v8" => "1a68f44598462abfade0dbeb6adf10b52614ba03605a8bf487b99493deb41468317926ef2d657479fcc26fce640aeebdbd880956beec3fb110b5abc97bd83556",
    _ => panic!("unsupported platform"),
  };

  #[rustfmt::skip]
  let download_nimbus = format!(r#"
FROM alpine:latest as nimbus

ENV NIMBUS_VERSION=24.3.0
ENV NIMBUS_COMMIT=dc19b082

# Download nimbus
RUN wget https://github.com/status-im/nimbus-eth2/releases/download/v${{NIMBUS_VERSION}}/nimbus-eth2_Linux_{platform}_${{NIMBUS_VERSION}}_${{NIMBUS_COMMIT}}.tar.gz

# Extract nimbus
RUN tar xvf nimbus-eth2_Linux_{platform}_${{NIMBUS_VERSION}}_${{NIMBUS_COMMIT}}.tar.gz
RUN mv nimbus-eth2_Linux_{platform}_${{NIMBUS_VERSION}}_${{NIMBUS_COMMIT}}/build/nimbus_beacon_node ./nimbus

# Verify the checksum
RUN sha512sum nimbus | grep {checksum}
"#);

  let run_nimbus = format!(
    r#"
COPY --from=nimbus --chown=ethereum nimbus /bin

ADD /orchestration/{}/coins/ethereum/consensus/nimbus/run.sh /consensus_layer.sh
"#,
    network.label()
  );

  (download_nimbus, String::new(), run_nimbus)
}
