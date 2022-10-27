#!/usr/bin/env bash

root_dir=$(git rev-parse --show-toplevel)

#NODE PORT
node_port=9912
node_url=ws://integritee-node

worker_url=wss://tee-builder
worker_port=2000

CLIENT="./integritee-cli --node-url ${node_url} --node-port ${node_port} --worker-url ${worker_url} --trusted-worker-port  ${worker_port}"


cd "${root_dir}"/bin
./integritee-service mrenclave | tee ~/mrenclave.b58
MRENCLAVE=$(cat ~/mrenclave.b58)

cd "${root_dir}"/tmp/worker1

RUST_LOG=warn ${CLIENT} shield-funds //Alice //Bob 1000000000000 H8wzxGBcKa1k5tXMALACo9P7uKS5rYFL8e3mMAEVe7Ln
RUST_LOG=warn ${CLIENT} shield-funds //Alice //Charlie 1000000000000 H8wzxGBcKa1k5tXMALACo9P7uKS5rYFL8e3mMAEVe7Ln
