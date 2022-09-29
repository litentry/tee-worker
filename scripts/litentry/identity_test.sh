#!/usr/bin/env bash

root_dir=$(git rev-parse --show-toplevel)

#CLIENT_BIN="$root_dir/bin/integritee-cli"

#NODE PORT
node_port=9912
node_url=ws://integritee-node

worker_url=wss://tee-builder
worker_port=2000

CLIENT="./integritee-cli --node-url ${node_url} --node-port ${node_port} --worker-url ${worker_url} --trusted-worker-port  ${worker_port}"
#cd ${root_dir}/tmp/worker1

cd ${root_dir}/bin
./integritee-service mrenclave | tee ~/mrenclave.b58
MRENCLAVE=$(cat ~/mrenclave.b58)

cd ${root_dir}/tmp/worker1
#ICGACCOUNTALICE=//AliceIncognito

#echo "* Get balance of Alice's incognito account"
#RESULT=$(${CLIENT} trusted --mrenclave ${MRENCLAVE} balance jcSzFSSdD3A1hLbknjLnEWbGQsaVJoPEzHskQZHZ4iXuY9Cwo | xargs)
#echo $RESULT
#echo ""

#echo "query-credit: https test"
#${CLIENT} trusted --mrenclave ${MRENCLAVE} query-credit "//Alice"
#echo ""

# node-js:  tweet_id: Buffer.from("1571829863862116352").toJSON().data.toString()
validation_data='{"Web2":{"Twitter":{"tweet_id":[49,53,55,49,56,50,57,56,54,51,56,54,50,49,49,54,51,53,50]}}}'

# node-js:  twitter_username: Buffer.from("litentry").toJSON().data.toString()
identity='{"web_type":{"Web2":"Twitter"},"handle":{"String":[108,105,116,101,110,116,114,121]}}'

echo "link_identity"
RUST_LOG=warn ${CLIENT} trusted --mrenclave ${MRENCLAVE} link-identity "//Alice" "$identity"

echo "set-challenge-code"
${CLIENT} trusted --mrenclave ${MRENCLAVE} set-challenge-code "//Alice" "$identity" 1134

echo "verify-identity"
RUST_LOG=info ${CLIENT} trusted --mrenclave ${MRENCLAVE} prepare-verify-identity "//Alice" "$identity" "$validation_data"
