#!/bin/bash

set -ex

HIBE_ENCRYPTOR=$1

depths=(5 10 20 30 40)

make clean_results

for depth in ${depths[@]}; do
	make clean; make SGX_MODE=HW NUM_PAD_PAGES=1 HIBE_DEPTH=$depth HIBE_ENCRYPTOR=$HIBE_ENCRYPTOR
        ./run_bench.sh 100 $depth
done
