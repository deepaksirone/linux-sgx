#!/usr/bin/python

import sys

def main():
    page_size = 4096
    print("const char *big_data = (const char *)\"" + "A" * (int(sys.argv[1]) * page_size) + "\";")
main()
