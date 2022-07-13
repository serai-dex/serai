# Optimized Schnorr verification contract

This repo contains a contract `Schnorr.sol` which verifies a (modified) Schnorr signature using only `ecrecover` and `keccak256`. 

Total gas cost: `29707`

### How it works

See https://hackmd.io/@nZ-twauPRISEa6G9zg3XRw/SyjJzSLt9

### Try it out

Compile:
```
npx hardhat compile
```

Test:
```
npx hardhat test
```