#!/usr/bin/python

import sys
import statistics as stat

def main():
    output_file = sys.argv[1]
    init_times = []
    decryption_times = []
    with open(output_file, "r+") as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            sp = line.split()
            if len(sp) > 3:
                if sp[0] == 'Decryption' and sp[1] == 'Elapsed' and sp[2] == 'time:':
                    decryption_times = decryption_times + [float(sp[3])]
            if len(sp) > 3:
                if sp[0] == 'Init':
                    init_times = init_times + [float(sp[3])]

        print ("Mean Decryption Time: " + str(stat.mean(decryption_times)))
        print ("Stdev of Decryption Time: " + str(stat.stdev(decryption_times)))
        print ("Mean Init Time: " + str(stat.mean(init_times)))
        print ("Stdev of Init Time: " + str(stat.stdev(init_times)))
main()
