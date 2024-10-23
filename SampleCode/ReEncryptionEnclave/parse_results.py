#!/usr/bin/python

import sys
import statistics as stat

def main():
    output_file = sys.argv[1]
    #init_times = []
    re_times = []
    with open(output_file, "r+") as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            sp = line.split()
            if len(sp) > 3:
                if sp[0] == 'reEncryption' and sp[1] == 'Elapsed':
                    re_times = re_times + [float(sp[3])]
            #if len(sp) > 3:
            #    if sp[0] == 'Total' and sp[1] == 'Init':
            #        init_times = init_times + [float(sp[3])]

        print ("Mean ReEncryption Time: " + str(stat.mean(re_times)))
        print ("Stdev of ReEncryption Time: " + str(stat.stdev(re_times)))
        #print ("Mean Init Time: " + str(stat.mean(init_times)))
        #print ("Stdev of Init Time: " + str(stat.stdev(init_times)))
main()