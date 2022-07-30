#!/bin/bash
set -euo pipefail

PARACHAIN_DIR=/tmp/litentry-parachain
[ -d "$PARACHAIN_DIR" ] && rm -rf "$PARACHAIN_DIR"
git clone https://github.com/litentry/litentry-parachain "$PARACHAIN_DIR"
cd "$PARACHAIN_DIR"
git checkout tee-dev

./scripts/build-docker.sh release tee-dev --features=tee-dev