#!/usr/bin/python

import sys
from pathlib import Path

def main():
    fname = sys.argv[1]
    splits = fname.split('_')
    num_times = int(splits[1])
    latency = int(splits[2])
 
    fname = open(sys.argv[1], "r+")

    lines = fname.readlines()
    # print (lines)
    mean_ra_time = lines[0].split(" ")[3].strip()
    stdev_ra_time = lines[1].split(" ")[4].strip()
    mean_init_time = lines[2].split(" ")[3].strip()
    stdev_init_time = lines[3].split(" ")[4].strip()

    csv_fname = "csv_ra_" + str(num_times)

    csv_file = Path(csv_fname)
    if not csv_file.exists():
        # Create a file with the name and the comma separated headings
        f = open(csv_fname, "w+")
        
        f.write("Latency, Mean RA Time, Stdev of RA Time, Mean Init Time, Stdev of Init Time\n")
        # print (mean_dec_time, stdev_dec_time, mean_init_time, stdev_init_time)
        row = "{latency}, {mean_ra_time}, {stdev_ra_time}, {mean_init_time}, {stdev_init_time}\n".format(latency=latency, mean_ra_time=mean_ra_time, stdev_ra_time=stdev_ra_time, mean_init_time=mean_init_time, stdev_init_time=stdev_init_time)
        print (row)
        f.write(row)
        f.close()
    else:
        f = open(csv_fname, "a")

        f.write("{latency}, {mean_ra_time}, {stdev_ra_time}, {mean_init_time}, {stdev_init_time}\n".format(latency = latency, mean_ra_time=mean_ra_time,
                                                                                                             stdev_ra_time=stdev_ra_time,
                                                                                                             mean_init_time=mean_init_time, stdev_init_time=stdev_init_time))
        f.close()
main()

