#!/bin/bash

set -ex

pages=(1 10 20 30 40 50 100 500 700 1000 2000 5000 10000)

for page in ${pages[@]}; do
	#make clean
	make clean; make SGX_MODE=HW NUM_PAD_PAGES=$page
	./run_bench.sh 100 $page
done	
