#!/usr/local/bin/python2.7
from __future__ import division
import sys, socket
import dpkt

counter=0
ipcounter=0
tcpcounter=0
udpcounter=0

dstip = '192.168.8.130'
last_t = 0.0
current = 0.0
flow_count = 0
total =  0.0
max_time = 0.0
min_time = 9999999.0

filename='sample.pcap'

last_t
for ts, pkt in dpkt.pcap.Reader(open(filename,'r')):

    counter+=1
    eth=dpkt.ethernet.Ethernet(pkt) 
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
       continue

    ip=eth.data
    ipcounter+=1

    if ip.p==dpkt.ip.IP_PROTO_TCP: 
       tcpcounter+=1

    if ip.p==dpkt.ip.IP_PROTO_UDP:
       udpcounter+=1

    src = socket.inet_ntoa(ip.src)
    dst = socket.inet_ntoa(ip.dst)
    if dst == dstip:
	flow_count += 1
	if flow_count == 1:
		last_t = ts
	else:
		current = ts
		total += current - last_t
		if (current - last_t) > max_time:
			max_time = current - last_t
		if (current - last_t) < min_time:
			min_time = current - last_t
		last_t = current
			
    print "%f: %s -> %s" % (ts, src, dst)

print 'avg, max, min: ', total/(flow_count - 1), max_time, min_time 
print "Total number of packets in the pcap file: ", counter
print "Total number of ip packets: ", ipcounter
print "Total number of tcp packets: ", tcpcounter
print "Total number of udp packets: ", udpcounter
