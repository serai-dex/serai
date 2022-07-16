#!/bin/bash
BASEDIR=$(pwd)
git submodule update --init --recursive
sudo apt-get install libgtest-dev && cd /usr/src/gtest && sudo cmake . && sudo make
sudo mv lib/libg* /usr/lib/
cd ${BASEDIR}
sudo apt update && sudo apt install build-essential cmake pkg-config libssl-dev libzmq3-dev libunbound-dev libsodium-dev libunwind8-dev liblzma-dev libreadline6-dev libldns-dev libexpat1-dev libpgm-dev qttools5-dev-tools libhidapi-dev libusb-1.0-0-dev libprotobuf-dev protobuf-compiler libudev-dev libboost-chrono-dev libboost-date-time-dev libboost-filesystem-dev libboost-locale-dev libboost-program-options-dev libboost-regex-dev libboost-serialization-dev libboost-system-dev libboost-thread-dev python3 ccache doxygen graphviz libboost-serialization-dev libboost-system-dev libboost-thread-dev python3 ccache doxygen graphviz
cargo build --all