#!/bin/bash

num_times=$1
num_pages=$2
i=0

while [ $i -lt $num_times ]; do
	./app >> out_$num_times\_$num_pages
	i=$(($i + 1))
done

python3 parse_results.py out_$num_times\_$num_pages > results_$num_times\_$num_pages