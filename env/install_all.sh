#!/usr/bin/env bash

set -eux

apt update
apt install python3-pip cmake ninja-build libpcap-dev unzip -y

BASE_NAME=$(basename $(pwd))

readonly BASE_NAME

# Install mlpack (Note that, mlpack repo. is stable.)
apt install libmlpack-dev mlpack-bin libarmadillo-dev -y

# Install GFlags
apt install libgflags-dev -y

# Install other python libraries
pip3 install matplotlib scikit-learn
wget https://download.pytorch.org/libtorch/cpu/libtorch-shared-with-deps-2.8.0%2Bcpu.zip
unzip libtorch-shared-with-deps-2.8.0+cpu.zip && rm libtorch-shared-with-deps-2.8.0+cpu.zip

cd env
chmod +x install_pcapp.sh
./install_pcapp.sh