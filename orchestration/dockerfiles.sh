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

# Message Queue
rm ./message-queue/Dockerfile
cat \
  ./Dockerfile.parts/mimalloc/Dockerfile.debian \
  ./Dockerfile.parts/Dockerfile.serai.build \
  ./message-queue/Dockerfile.message-queue \
  ./Dockerfile.parts/Dockerfile.debian.start \
  ./message-queue/Dockerfile.message-queue.end >> ./message-queue/Dockerfile

# Processor
rm ./processor/Dockerfile
cat \
  ./Dockerfile.parts/mimalloc/Dockerfile.debian \
  ./Dockerfile.parts/Dockerfile.serai.build \
  ./processor/Dockerfile.processor \
  ./Dockerfile.parts/Dockerfile.debian.start \
  ./processor/Dockerfile.processor.end >> ./processor/Dockerfile

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
