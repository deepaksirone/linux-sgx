#!/bin/bash

num_times=$1
num_pages=$2
hibe_depth=$3
i=0

while [ $i -lt $num_times ]; do
	./app >> out_$num_times\_$num_pages\_$hibe_depth
	i=$(($i + 1))
done

python3 parse_results.py out_$num_times\_$num_pages\_$hibe_depth > results_$num_times\_$num_pages\_$hibe_depth
python3 generate_csv.py results_$num_times\_$num_pages\_$hibe_depth
