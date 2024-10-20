#!/bin/bash

set -ex

pages=(1 10 20 30 40 50 100 500 700 1000 2000 5000 10000)
depths=(5 10 20 30 40)

make clean_results

for depth in ${depths[@]}; do
	#make clean
	for page in ${pages[@]}; do
		make clean; make SGX_MODE=SW NUM_PAD_PAGES=1 HIBE_DEPTH=40 HIBE_ENCRYPTOR=$1
		./run_bench.sh 100 $page $depth
	done
done

