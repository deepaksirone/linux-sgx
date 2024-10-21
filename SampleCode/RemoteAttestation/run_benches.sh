#!/bin/bash

set -ex

SGX_SDK_ENV=$1
source $1

latencies=(0 10 20 30 40 50 60 70 80 90 100)
make clean; make clean_results; make SGX_MODE=HW
make server
echo "Starting Server"
pushd service_provider
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/../ ./server &
popd

for latency in ${latencies[@]}; do
        #make clean; make SGX_MODE=HW
	tc qdisc del dev lo root netem || true
	tc qdisc add dev lo root netem delay "${latency}ms"
        ./run_bench.sh 100 $latency
done
