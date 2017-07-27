#!/usr/bin/env python

"""
do_line_diff.py - Interactively runs all tests, and on any test where line_diff.py
showed an output, lets the user check the output and replace the test file with the output
file if they think it's safe to do so (in the sense that the test is actually passing). This
script was first used when enhancing the ssl protocol to not immediately stop detection upon
only detecting a client certificate. When server certificates were added, the this script
was helpful in checking which lines of which tests had appended server certificate info
to the line.
"""

import os
import sys
import time
import subprocess

program_base_args = ["../example/ndpiReader", "-p", "../example/protos.txt", "-q", "-i"]
line_diff_base_args = ["./line_diff.py"]
temp_output = "/tmp/reader.out"
result_folder = "result/"
pcap_folder = "pcap/"
pcap_file_list = os.listdir(pcap_folder)

def find_pcap(result_file):
    for pcap_file in pcap_file_list:
        if pcap_file == result_file[:-4]:
            return pcap_file

for result_file in os.listdir(result_folder):
    pcap_file = find_pcap(result_file)
    program_args = program_base_args + [pcap_folder + pcap_file, "-w", temp_output, "-v", "1"]
    program_output = subprocess.call(program_args)
    line_diff_args = line_diff_base_args + [result_folder + result_file, temp_output]
    line_diff_output = subprocess.check_output(line_diff_args, universal_newlines=True)
    if len(line_diff_output) > 0:
        print("File output " + result_file + " had line diff output. Here it is:")
        print(line_diff_output)
        replace = ""
        while replace.lower() != 'y' and replace.lower() != 'n':
            replace = input("Would you like to replace the file? ('y' or 'n') ")
            if replace == 'y':
                subprocess.check_output(["cp", temp_output, result_folder + result_file])
                print("")
            elif replace == 'n':
                break