# serai-mock-rpc

In-process **mock Serai RPC node**, wire-compatible with the production `Serai` RPC serai (`serai-client-serai`).

- Binds to an ephemeral `127.0.0.1` port and implements some RPC methods the real node exposes (`blockchain/*`, `validator-sets/*`, ...);
- Lets tests **pre-populate blocks with arbitrary events** (allocations, SetDecided, SetKeys, etc.) so the exact scenario is fully controlled;
- Supports **dynamic block addition** (`add_block_with_events`) and **error injection** (`set_error` / `clear_error`) during a test;
- Builds blocks using the same `IncrementalUnbalancedMerkleTree` + `BLOCK_BRANCH_TAG`/`BLOCK_LEAF_TAG` logic as the real chain, so `builds_upon` hashes are valid.

## Example

```rust
use serai_mock_rpc::{MockSeraiRpc, MockSeraiState};
use serai_client_serai::Serai;

let mut state = MockSeraiState::default();
state.make_block(0, vec![vec![]]);
state.make_block(1, vec![vec![allocation_event(...), set_keys_event(...)]]);

let mock_serai = MockSeraiRpc::start(state).await;
let serai = Serai::new(mock_serai.url()).unwrap();

let latest = serai.latest_finalized_block_number().await.unwrap();
assert_eq!(latest, 1);
```
