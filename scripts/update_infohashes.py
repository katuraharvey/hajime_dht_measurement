#!/bin/python

import datetime
import sys
import os
import subprocess

TMP_FILENAME = 'infohashes_tmp.txt'
INFOHASH_PATH = '/home/ubuntu/hajime_dht_measurement/config/infohashes.txt'

now = datetime.datetime.utcnow()
time_diff = datetime.timedelta(days=2)
start_date = (now - time_diff).strftime("%Y-%m-%d")
end_date = (now + time_diff).strftime("%Y-%m-%d")

out = open(TMP_FILENAME, 'a')
subprocess.call(["python", "/home/ubuntu/hajime_dht_measurement/scripts/generate_infohashes_date_range.py", "config", start_date, end_date], stdout=out)
subprocess.call(["python", "/home/ubuntu/hajime_dht_measurement/scripts/get_infohashes_from_config.py", 
    "/home/ubuntu/hajime_dht_measurement/config/config.file", start_date, end_date], stdout=out)
os.system("cp %s %s"%(TMP_FILENAME, INFOHASH_PATH))
out.close()
os.system("rm %s"%TMP_FILENAME)
