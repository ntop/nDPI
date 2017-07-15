#!/usr/bin/env python
"""
line_diff.py - Simple tool that compares two files with the same number of lines and prints the
characters (if any) on the right line (moving left to right) that are present that
weren't present in the left line
"""

import sys

left_file = sys.argv[1]
right_file = sys.argv[2]

left_lines = []
right_lines = []

with open(left_file) as left:
    for line in left.readlines():
        left_lines.append(line.strip())
with open(right_file) as right:
    for line in right.readlines():
        right_lines.append(line.strip())

if len(left_lines) != len(right_lines):
    print("Files didn't have the same number of lines, exiting...")
    sys.exit(0)

for i in range(len(left_lines)):
    left_contents = left_lines[i]
    right_contents = right_lines[i]
    if len(left_contents) > len(right_contents):
        print("Line " + str(i) + " has longer left contents than right contents.")
        print("Left contents: " + left_contents)
        print("Right contents: " + right_contents)
        break
    else:
        left_list = list(left_contents)
        right_list = list(right_contents)
        while len(left_list) > 0:
            if right_list.pop(0) != left_list.pop(0):
                print("Line " + str(i) + ": Right contents that are not a prefix of left contents.")
                print("Left contents: " + left_contents)
                print("Right contents: " + right_contents)
                break
        if len(right_list) > 0:
            print("Line " + str(i) + ": Right contents have extra characters: " + ''.join(right_list))
