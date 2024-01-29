# Bitcoin
rm ./coins/bitcoin/Dockerfile
cat \
  ./Dockerfile.parts/mimalloc/Dockerfile.debian \
  ./coins/bitcoin/Dockerfile.bitcoin \
  ./Dockerfile.parts/Dockerfile.debian.start \
  ./coins/bitcoin/Dockerfile.bitcoin.end >> ./coins/bitcoin/Dockerfile

# Monero
rm ./coins/monero/Dockerfile
cat \
  ./Dockerfile.parts/mimalloc/Dockerfile.alpine \
  ./coins/monero/Dockerfile.monero \
  ./Dockerfile.parts/Dockerfile.alpine.start \
  ./coins/monero/Dockerfile.monero.end >> ./coins/monero/Dockerfile

# Monero wallet rpc
rm -f ./coins/monero-wallet-rpc/Dockerfile
mkdir -p ./coins/monero-wallet-rpc/temp/
cp ./coins/monero/temp/hashes-v* ./coins/monero-wallet-rpc/temp/
cat \
  ./Dockerfile.parts/mimalloc/Dockerfile.debian \
  ./coins/monero/Dockerfile.monero \
  ./Dockerfile.parts/Dockerfile.debian.start \
  ./coins/monero-wallet-rpc/Dockerfile.monero-wallet-rpc.end >> ./coins/monero-wallet-rpc/Dockerfile

# Message Queue
rm ./message-queue/Dockerfile
cat \
  ./Dockerfile.parts/mimalloc/Dockerfile.debian \
  ./Dockerfile.parts/Dockerfile.serai.build \
  ./message-queue/Dockerfile.message-queue \
  ./Dockerfile.parts/Dockerfile.debian.start \
  ./message-queue/Dockerfile.message-queue.end >> ./message-queue/Dockerfile

# Bitcoin Processor
rm ./processor/bitcoin/Dockerfile
cat \
  ./Dockerfile.parts/mimalloc/Dockerfile.debian \
  ./Dockerfile.parts/Dockerfile.serai.build \
  ./processor/bitcoin/Dockerfile.processor.bitcoin \
  ./Dockerfile.parts/Dockerfile.debian.start \
  ./processor/Dockerfile.processor.end >> ./processor/bitcoin/Dockerfile

# Monero Processor
rm ./processor/monero/Dockerfile
cat \
  ./Dockerfile.parts/mimalloc/Dockerfile.debian \
  ./Dockerfile.parts/Dockerfile.serai.build \
  ./processor/monero/Dockerfile.processor.monero \
  ./Dockerfile.parts/Dockerfile.debian.start \
  ./processor/Dockerfile.processor.end >> ./processor/monero/Dockerfile

# Coordinator
rm ./coordinator/Dockerfile
cat \
  ./Dockerfile.parts/mimalloc/Dockerfile.debian \
  ./Dockerfile.parts/Dockerfile.serai.build \
  ./coordinator/Dockerfile.coordinator \
  ./Dockerfile.parts/Dockerfile.debian.start \
  ./coordinator/Dockerfile.coordinator.end >> ./coordinator/Dockerfile

# Node
rm ./serai/Dockerfile
cat \
  ./Dockerfile.parts/mimalloc/Dockerfile.debian \
  ./Dockerfile.parts/Dockerfile.serai.build \
  ./serai/Dockerfile.serai \
  ./Dockerfile.parts/Dockerfile.debian.start \
  ./serai/Dockerfile.serai.end >> ./serai/Dockerfile
