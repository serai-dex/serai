# Deploy
## Run with Docker Compose
Running the Serai infrastructure is easy with Docker.

We utilize compose profiles to easily orchestrate various pieces of the infrastructure.

**Example:** `docker compose --profile cluster-coins-sm up`

All commands are assumed to be ran from the deploy folder, not the serai root folder.

### Profiles:
* base - single node, named base
* coins - node clients for coins only (BTC, ETH, XMR)
* cluster-sm - Alice (Validator), Bob, Charlie
* cluster-coins-sm - cluster-sm with coins
* cluter-lg - Alice (Validator), Bob, Charlie, Dave, Eve, Ferdie
* cluster-coins-lg - cluster-lg with coins
* monero - full node monero only
* bitcoin - full node bitcoin only
* ethereum - full node ethereum only

You can supply one or more profiles to the docker compose command to orchestrate the desired components.

**Example:** `docker compose --profile base --profile bitcoin up`

## Orchestration Approach
### Builds
The Serai node is the only piece of our infrastructure that we compile locally and for the first build, it can take 10 minutes or more to complete the image. Images for external coins download binaries, then verify the signatures and checksums of the build. Overall the standard image build process looks like:

**Stage 1 -- Builder**
* Configure environment.
* Get the binary.
* Verify binary using GPG.
* Uncompress binary to prepare image.

**Stage 2 -- Image**
* Copy needed files from builder.
* Move executables to bin folder.
* Copy scripts folder.
* Expose necessary ports.
* Map necessary volumes.

The best way is to build using docker compose, but if you prefer to build using docker directly, each image can be built directly.

**Example:** `docker build ./coins/bitcoin`

### Entrypoint
The Serai full node and external full nodes each are started from an entrypoint script inside the /scripts folder.

To update the scripts on the image you must rebuild the updated images using the --build flag after "up" in docker compose.

**Example:** `docker compose --profile bitcoin up --build`
