import sys
from generate_infohashes_date_range import generate_infohashes
import string 

f = open(sys.argv[1])
for line in f.readlines():
    if line.startswith('[modules]'):
        continue
    elif line.startswith('[peers]'):
        break
    if(len(sys.argv) == 2):
        generate_infohashes(line.rstrip())
    elif(len(sys.argv) == 4):
        generate_infohashes(line.rstrip(), sys.argv[2], sys.argv[3])
    else:
        print "usage: generate_infohashes_date_range.py <filename> <start_date> <end_date>"
