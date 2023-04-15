use serai_client::{SeraiError, Block, Serai};

async fn handle_block(serai: &Serai, block: Block) -> Result<Vec<()>, SeraiError> {
  let hash = block.hash();
  let mut actions = vec![];

  // If a new validator set was activated, create tributary/inform processor to do a DKG
  for new_set in serai.get_new_set_events(hash).await? {
    todo!()
  }

  // If a key pair was confirmed, inform the processor
  for key_gen in serai.get_key_gen_events(hash).await? {
    todo!()
  }

  // If batch, tell processor of block acknowledged/burns
  for new_set in serai.get_batch_events(hash).await? {
    todo!()
  }

  Ok(actions)
}

pub(crate) async fn handle_new_blocks(
  serai: &Serai,
  last_substrate_block: &mut u64,
) -> Result<(), SeraiError> {
  // Check if there's been a new Substrate block
  let latest = serai.get_latest_block().await?;
  let latest_number = latest.number();
  if latest_number == *last_substrate_block {
    return Ok(());
  }
  let mut latest = Some(latest);

  for b in (*last_substrate_block + 1) ..= latest_number {
    let actions = handle_block(
      serai,
      if b == latest_number {
        latest.take().unwrap()
      } else {
        serai.get_block_by_number(b).await?.unwrap()
      },
    )
    .await?;
    // TODO: Handle actions, update the DB
    *last_substrate_block += 1;
  }

  Ok(())
}
