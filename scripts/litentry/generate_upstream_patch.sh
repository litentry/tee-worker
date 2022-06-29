#!/bin/bash

set -eo pipefail

cleanup() {
  rm -rf "$1"
  echo "cleaned up $1"
}

# This script generates a patch for the diffs between commit-A and commit-B
# of the upstream repo (https://github.com/integritee-network/worker), where
# commit-A: the commit recorded in tee-worker/upstream_commit
# commit-B: the HEAD commit of upstream master
#
# The patch will be generated under tee-worker/upstream.patch
# to apply this patch:
# git apply --reject upstream.patch

UPSTREAM="https://github.com/integritee-network/worker"
ROOTDIR=$(git rev-parse --show-toplevel)
cd "$ROOTDIR"

if [ -f upstream_commit ]; then
    OLD_COMMIT=$(head -1 upstream_commit)
else
    echo "Can't find upstream_commit file, quit"
    exit 1
fi

TMPDIR=$(mktemp -d)
trap 'cleanup "$TMPDIR"' ERR EXIT INT

cd "$TMPDIR"
echo "cloning $UPSTREAM ..."
git clone -q "$UPSTREAM" worker
cd worker
echo "generating patch ..."
git diff $OLD_COMMIT HEAD > "$ROOTDIR/upstream.patch"

echo "====================================="
echo "upstream.patch is generated, please:"
echo '- run `git apply --reject upstream.patch` to apply it'
echo "- manually resolve any rejected parts"
echo "- be sure to update upstream_commit after merging"
echo "====================================="