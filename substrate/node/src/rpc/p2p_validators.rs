use super::*;

pub(crate) fn module(
  bootnodes: &[MultiaddrWithPeerId],
  client: Arc<FullClient>,
  authority_discovery: sc_authority_discovery::Service,
) -> Result<RpcModule<impl 'static + Send + Sync>, Box<dyn std::error::Error + Send + Sync>> {
  let bootnodes = bootnodes.iter().map(ToString::to_string).collect::<Vec<_>>();
  let mut module =
    RpcModule::new((bootnodes, client, tokio::sync::RwLock::new(authority_discovery)));

  module.register_async_method("p2p_validators", async move |params, context, _ext| {
    let network = match params.parse::<[String; 1]>() {
      Ok([network]) => network,
      Err(e) => return Err(e),
    };

    let network = network_from_str(network)?;
    let (bootnodes, client, authority_discovery) = &*context;
    let latest_block = client.info().best_hash;

    // Always return the protocol's bootnodes
    let mut all_p2p_addresses = bootnodes.clone();

    // Additionally return validators found over the DHT
    let validators = client
      .runtime_api()
      .validators_for_peering(latest_block, network)
      .map_err(|_| Error::Internal("couldn't get validators from the latest block"))?;
    for validator in validators {
      let mut returned_addresses = authority_discovery
        .write()
        .await
        .get_addresses_by_authority_id(validator)
        .await
        .unwrap_or_else(HashSet::new)
        .into_iter()
        .collect::<Vec<_>>();

      /*
        Randomly select an address.

        While an address may have multiple address during a transition period, or due to some
        proxy/load balancing setup, it isn't beneficial to return the same validator multiple times
        here.

        TODO: Currently, this returns the `Multiaddr` _sans `PeerId`_. We should define `PeerId`s
        on our other P2P network such that there is a map from one to the other. This would allow
        us to dial a peer _by `PeerId`_, instead of by `Multiaddr` without `PeerId` as this forces.
      */
      if !returned_addresses.is_empty() {
        all_p2p_addresses.push(
          returned_addresses
            .remove(usize::try_from(OsRng.next_u64() >> 32).unwrap() % returned_addresses.len())
            .to_string(),
        );
      }
    }

    Ok(all_p2p_addresses)
  })?;

  Ok(module)
}
