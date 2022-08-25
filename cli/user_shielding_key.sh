#!/bin/bash

ROOTDIR=$(git rev-parse --show-toplevel)
cd "$ROOTDIR"

while getopts ":m:p:P:t:u:V:C:" opt; do
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
            WORKER1PORT=$OPTARG
            ;;
        u)
            NODEURL=$OPTARG
            ;;
        V)
            WORKER1URL=$OPTARG
            ;;
        C)
            CLIENT_BIN=$OPTARG
            ;;
    esac
done

# Using default port if none given as arguments.
NPORT=${NPORT:-9944}
NODEURL=${NODEURL:-"ws://127.0.0.1"}

WORKER1PORT=${WORKER1PORT:-2000}
WORKER1URL=${WORKER1URL:-"wss://127.0.0.1"}

CLIENT_BIN=${CLIENT_BIN:-"./bin/integritee-cli"}

echo "Using client binary $CLIENT_BIN"
echo "Using node uri $NODEURL:$NPORT"
echo "Using trusted-worker uri $WORKER1URL:$WORKER1PORT"
echo ""

ICGACCOUNTALICE=//AliceIncognito
KEY="abcdefd/+23one"

CLIENT="$CLIENT_BIN -p $NPORT -P $WORKER1PORT -u $NODEURL -U $WORKER1URL"
echo "CLIENT is $CLIENT"

echo "* Query on-chain enclave registry:"
$CLIENT list-workers
echo ""

if [ "$READMRENCLAVE" = "file" ]
then
    read MRENCLAVE <<< $(cat ~/mrenclave.b58)
    echo "Reading MRENCLAVE from file: ${MRENCLAVE}"
else
    # This will always take the first MRENCLAVE found in the registry !!
    read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE: / { print $2; exit }')
    echo "Reading MRENCLAVE from worker list: ${MRENCLAVE}"
fi
[[ -z $MRENCLAVE ]] && { echo "MRENCLAVE is empty. cannot continue" ; exit 1; }

echo "* Get balance of Alice's on-chain account"
$CLIENT balance "//Alice"
echo ""

sleep 10
echo "* Get balance of Alice's sidechain account"
$CLIENT trusted --mrenclave $MRENCLAVE --direct balance "//Alice"
echo ""

# direct calls
sleep 10
echo "* Set $ICGACCOUNTALICE 's shielding key to $KEY"
$CLIENT trusted --mrenclave $MRENCLAVE --direct set-shielding-key $ICGACCOUNTALICE "$KEY"
echo ""

sleep 10
echo "* Get $ICGACCOUNTALICE 's shielding key"
ACTUAL_KEY=$($CLIENT trusted --mrenclave $MRENCLAVE --direct shielding-key $ICGACCOUNTALICE)
echo ""

if [ "$ACTUAL_KEY" = "$KEY" ]; then
    echo "KEY identical: $KEY"
    echo "test direct call passed"
else
    echo "KEY non-identical: expected: $KEY actual: $ACTUAL_KEY"
    exit 1
fi

# change KEY
KEY="abcdefd/+23two"

# indirect calls
sleep 10
echo "* Set $ICGACCOUNTALICE 's shielding key to $KEY"
$CLIENT trusted --mrenclave $MRENCLAVE set-shielding-key $ICGACCOUNTALICE "$KEY"
echo ""

sleep 10
echo "* Get $ICGACCOUNTALICE 's shielding key"
ACTUAL_KEY=$($CLIENT trusted --mrenclave $MRENCLAVE --direct shielding-key $ICGACCOUNTALICE)
echo ""

if [ "$ACTUAL_KEY" = "$KEY" ]; then
    echo "KEY identical: $KEY"
    echo "test indirect call passed"
else
    echo "KEY non-identical: expected: $KEY actual: $ACTUAL_KEY"
    exit 1
fi

exit 0
