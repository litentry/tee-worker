#!/bin/bash
set -euo pipefail

PARACHAIN_DIR=/tmp/litentry-parachain
[ -d "$PARACHAIN_DIR" ] && rm -rf "$PARACHAIN_DIR"
git clone https://github.com/litentry/litentry-parachain "$PARACHAIN_DIR"
cd "$PARACHAIN_DIR"

cp -f docker/litmus-parachain-launch-config.tee-dev.yml docker/litmus-parachain-launch-config.yml

make launch-docker-litmus