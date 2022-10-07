# Kubernetes
## Run with Kubernetes
Running the Serai infrastructure is easy with Kubernetes.

We utilize Makefile to easily orchestrate various pieces of the infrastructure on kubernetes.

**Example to deploy:** `make deploy-<Profile_Name>`
```bash
make deploy-cluster-sm
```
**Example to delete:** `make delete-<Profile_Name>`
```bash
make delete-cluster-sm
```

All commands are assumed to be ran from the kubernetes folder, not the serai root folder.

### Profiles:
* deploy-base - single node, named base
* deploy-coins - node clients for coins only (BTC, ETH, XMR)
* deploy-cluster-sm - Alice (Validator), Bob, Charlie
* deploy-cluster-coins-sm - cluster-sm with coins
* deploy-cluster-lg - Alice (Validator), Bob, Charlie, Dave, Eve, Ferdie
* deploy-cluster-coins-lg - cluster-lg with coins
* deploy-monero - full node monero only
* deploy-bitcoin - full node bitcoin only
* deploy-ethereum - full node ethereum only

## Requirements for Linux
* Local built images of serai and coins, please follow the Instructions [here](../README.md)
* Running kubernetes cluster (version >= 1.19)
* Curl tool
* Make tool
* Kubectl, check if not installed
```bash
make check-kubectl
```
* Helm, check if not installed
```bash
make check-helm
```
