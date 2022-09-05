#!/bin/bash

# setup:
# run all on localhost:
#   integritee-node purge-chain --dev
#   integritee-node --dev -lruntime=debug
#   rm light_client_db.bin
#   export RUST_LOG=integritee_service=info,ita_stf=debug
#   integritee-service init_shard
#   integritee-service shielding-key
#   integritee-service signing-key
#   integritee-service run
#
# then run this script

# usage:
#  export RUST_LOG_LOG=integritee-cli=info,ita_stf=info
#  demo_shielding_unshielding.sh -p <NODEPORT> -P <WORKERPORT> -t <TEST_BALANCE_RUN> -m file
#
# TEST_BALANCE_RUN is either "first" or "second"
# if -m file is set, the mrenclave will be read from file

while getopts ":m:p:P:t:" opt; do
    case $opt in
        t)
            TEST=$OPTARG
            ;;
        m)
            READMRENCLAVE=$OPTARG
            ;;
        p)
            NPORT=$OPTARG
            ;;
        P)
            RPORT=$OPTARG
            ;;
    esac
done

# using default port if none given as arguments
NPORT=${NPORT:-9944}
RPORT=${RPORT:-2000}

echo "Using node-port ${NPORT}"
echo "Using trusted-worker-port ${RPORT}"
echo ""

AMOUNTSHIELD=50000000000
AMOUNTTRANSFER=25000000000
AMOUNTUNSHIELD=15000000000

CLIENT="./../bin/integritee-cli -p ${NPORT} -P ${RPORT}"

echo "* Query on-chain enclave registry:"
${CLIENT} list-workers
echo ""

if [ "$READMRENCLAVE" = "file" ]
then
    read MRENCLAVE <<< $(cat ~/mrenclave.b58)
    echo "Reading MRENCLAVE from file: ${MRENCLAVE}"
else
    # this will always take the first MRENCLAVE found in the registry !!
    read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE: / { print $2; exit }')
    echo "Reading MRENCLAVE from worker list: ${MRENCLAVE}"
fi
[[ -z $MRENCLAVE ]] && { echo "MRENCLAVE is empty. cannot continue" ; exit 1; }


echo "query-credit: https test"
${CLIENT} trusted --mrenclave ${MRENCLAVE} query-credit "//Alice"
echo ""
