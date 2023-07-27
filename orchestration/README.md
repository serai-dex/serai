# Deploy

## Run with Docker Compose

Running the Serai infrastructure is easy with Docker.

We utilize compose profiles to easily orchestrate various pieces of the
infrastructure.

**Example:** `docker compose --profile cluster-coins-sm up`

All commands are assumed to be ran from `/deploy`, not the root folder.

### Profiles:

* `bitcoin`  - Bitcoin node
* `monero`   - Monero node
* `ethereum` - Ethereum node
* `coins`    - Nodes for all external networks (BTC, ETH, XMR)

* `message-queue` - The message queue service.
* `processor`     - Serai processor for one external network.

* `serai`      - Serai node
* `cluster-sm` - "Alice", "Bob", and "Charlie" Serai nodes, all validators
* `cluster-lg` - `cluster-sm` with non-validators "Dave", "Eve", and "Ferdie"

You can supply one or more profiles to the docker compose command to orchestrate
the desired components.

**Example:** `docker compose --profile coins --profile serai up`

## Orchestration Approach

### Builds

The Serai infrastructure is locally compiled. This may take several minutes.

Images for external networks download binaries, before verifying their checksums
and signatures.

**Stage 1 -- Builder**
* Configure environment.
* Get the binary.
* Verify binary using GPG.
* Decompress binary to prepare image.

**Stage 2 -- Image**
* Copy needed files from builder.
* Move executables to bin folder.
* Copy scripts folder.
* Expose necessary ports.
* Map necessary volumes.

### Entrypoint

The Serai node and external networks' nodes are each started from an entrypoint
script inside the `/scripts `folder.

To update the scripts on the image you must rebuild the updated images using the
`--build` flag after `up` in `docker compose`.

**Example:** `docker compose --profile bitcoin up --build`
