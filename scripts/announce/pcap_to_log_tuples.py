import sys
from scapy.all import *
import os
import re
from datetime import datetime
import time

PORT_MAP_FILE = "/home/ubuntu/hajime_dht_measurement/config/port_map.txt"
LOG_FILE = 'pcap_parse.log'
MIN_PORT = 20000
MAX_PORT = 60000
port_map = {}

log_file=open(LOG_FILE, 'a')

def load_port_map():
  port_map_file = open(PORT_MAP_FILE, 'r')
  for line in port_map_file.readlines():
    matches = re.search('(\d*) (\w*) ([\S]*) ([0-9\-]*)', line)
    if(matches):
      port = int(matches.group(1))
      port_map[port] = {'infohash':matches.group(2),
          'filename': matches.group(3),
          'date': matches.group(4)}
    else:
      log_file.write('Error parsing line %s\n'%line)
  port_map_file.close()

def convert_pcap(pcap_filename, output_dir=None):
    time_str = datetime.utcnow().strftime('%Y-%m-%d')
    if output_dir:
        output_file = '%s/%s.log' % (output_dir, time_str)
    else:
        output_file = '%s.log'%time_str
    output = open(output_file, 'a') 

    load_port_map()

    log_file.write('%d Parsing pcacp %s.\n'%(time.time(), pcap_filename))
    packets = rdpcap(pcap_filename)
    log_file.write('%d packets\n'%len(packets))
    count = 0
    for packet in packets:
      count += 1
      if 'IP' in packet and 'UDP' in packet:
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        packet_time = packet.time
        sport = int(packet['UDP'].sport)
        dport = int(packet['UDP'].dport)

        # sanity check:
        if dport < MIN_PORT or dport > MAX_PORT:
          log_file.write('Packet port out of range. Skipping:\n')
          log_file.write('%s\n'%packet.summary())
          continue

        # Reported udp len includes udp header, so subtract 8
        udp_len = packet['UDP'].len - 8
        
        # UDP length > 38  implies not not utp, so filter out
        if udp_len > 30:
          log_file.write('Packet has len %d. Skipping:\n'%udp_len)
          log_file.write('%s\n'%packet.summary())
          continue

        # Get the UTP header
        if 'Raw' not in packet['UDP']:
          log_file.write('Packet has no raw layer. Skipping:\n')
          continue
        else:
          utp_header = packet['UDP']['Raw'].load[:20]

        # Make sure this is a utp Syn message
        if utp_header[0] != chr(0x41):  
          log_file.write('Packet has is not a uTP Syn. Skipping:\n')
          continue

        # Get the payload info
        payload_start_port = (dport/50) * 50
        if payload_start_port not in port_map:
          log_file.write('Error: could not find port %d in port map. Skipping:\n'%dport)
          log_file.write('%s\n'%packet.summary())
          continue
        payload_dict = port_map[payload_start_port]
        output.write("%d %s %s %s leecher %s %d %d %s\n" % 
            (packet_time, payload_dict['filename'], payload_dict['date'], 
              payload_dict['infohash'], src_ip, sport, udp_len, 
              utp_header.encode('hex')))

    output.close()

def main(argv):
  if len(sys.argv) == 3:
    output_dir = None
  elif len(sys.argv) == 4:
    output_dir = sys.argv[3]
  else:
    print("Usage: -f|-d <pcap_file>|<pcap_directory> <output directory (optional)>");
    exit()
  
  if sys.argv[1] == '-f':
    convert_pcap(sys.argv[2], output_dir)
  elif sys.argv[1] == '-d':
    files = os.listdir(sys.argv[2])
    if len(files) == 0:
      print('No files found in %s' % sys.argv[2])
      exit()
    for file in files:
      pcap_path = '%s/%s'%(sys.argv[2], file)
      convert_pcap(pcap_path, output_dir)


if __name__ == '__main__':
    main(sys.argv)                                                                   
                               
