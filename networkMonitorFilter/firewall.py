#!/usr/bin/python

import subprocess
import threading
import argparse
import os
import signal
import time
import ast
import httplib, urllib
import requests
import json
from ConfigParser import SafeConfigParser
import sys

global path
global url
global interface
global ipv4_net
global ipv6_net
global freq

def sendFile(secs):
	print "sent file"
	global path, freq, url, ipv4_net, ipv6_net, interface
	if os.path.isfile('send.csv'):
		os.remove('send.csv')
	os.mknod('send.csv')
	cmd = "sudo tshark -2 -R \"udp.port eq 53\" -T fields -n -r "+ path + " -E separator=/t -e frame.time_epoch -e eth.src -e ip.src -e dns.qry.name|uniq -f 1 > send.csv"
	convert = subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)
	convert.wait()
	cmd = "sudo tshark -2 -R \"!(udp.port eq 53) && ip\" -T fields -n -r "+ path + " -E separator=/t -e frame.time_epoch -e eth.src -e ip.src -e ip.dst|uniq -f 1 >> send.csv"
	convert = subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)
	convert.wait()
	cmd = "sudo tshark -2 -R \"!(udp.port eq 53) && ipv6\" -T fields -n -r "+ path + " -E separator=/t -e frame.time_epoch -e eth.src -e ipv6.src -e ipv6.dst|uniq -f 1  >> send.csv"
	convert = subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)
	convert.wait()

	files = {'logFile': open('send.csv', 'rb')}
	r = requests.post(url, files=files,verify=False)
	src = r.json()	
	os.remove('send.csv')
	'''
	if src["src"] is not None:
		block_ip(src["src"])
	'''
	send = threading.Timer(secs, sendFile,[secs])
	send.daemon = True
	send.start()

def unblock_dns_to(dname):
        cmd = "sudo iptables -D FORWARD -m string --algo bm --string "+dname+" -m state --state NEW,ESTABLISHED,RELATED -j DROP"
        print cmd
        shell = subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)
        shell.wait()

def block_dns_to(dname):
 	cmd = "sudo iptables -A FORWARD -m string --algo bm --string "+dname+" -m state --state NEW,ESTABLISHED,RELATED -j DROP"
        print cmd
        shell = subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)
        shell.wait()

def unblock_mac(mac):
	cmd = "sudo iptables -D FORWARD -m mac --mac-source "+mac+" -m state --state NEW,ESTABLISHED,RELATED -j DROP"
	print cmd
        shell = subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)
        shell.wait()

def unblock_ip(ip):
	cmd = "sudo iptables -D FORWARD -s "+ip+" -m state --state NEW,ESTABLISHED,RELATED -j DROP"
	print cmd
        shell = subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)
        shell.wait()

def block_ip(ip):
	cmd = "sudo iptables -A FORWARD -s "+ip+" -m state --state NEW,ESTABLISHED,RELATED -j DROP"
	print cmd
        shell = subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)
        shell.wait()

def block_mac(mac):
	cmd = "sudo iptables -A FORWARD -m mac --mac-source "+mac+" -m state --state NEW,ESTABLISHED,RELATED -j DROP"
	print cmd
        shell = subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)
        shell.wait()

def terminate_tshark(process_name):
        os.system('pkill '+process_name)

def sigint_handler(signum, frame):
        #terminate_tshark("tshark")	
        exit(0)

def startCapture(cmd):	
	subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)

def parseConfig(file_path):
	global path, freq, url, ipv4_net, ipv6_net, interface
	parser = SafeConfigParser()
	parser.read(file_path)
	section = "firewall_config"
	if(parser.has_section(section)):
        	for candidate in [ 'capt_interface', 'capt_path', 'dest_url', 'send_freq','net_ipv4_addr','net_ipv6_addr']:
                	if(parser.has_option(section, candidate)):
                        	if(candidate == "capt_path"):
					path = parser.get(section, candidate)

                        	elif(candidate == "capt_interface"):
					interface = parser.get(section, candidate)

                        	elif(candidate == "dest_url"):
					url = parser.get(section, candidate)

                        	elif(candidate == "send_freq"):
					freq = parser.get(section, candidate)

                        	elif(candidate == "net_ipv4_addr"):
					ipv4_net = parser.get(section, candidate)

                        	elif(candidate == "net_ipv6_addr"):
					ipv6_net = parser.get(section, candidate)
                	else:
                        	print candidate + " not found."
                        	return 0

	else:
        	print "No section found : [firewall_config]"
		return 0
	return 1

        
def main():
	global path, freq, url, ipv4_net, ipv6_net, interface
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', '--configuration', dest='config',help='Configuration file path')
        args = parser.parse_args()

        if (args.config is None):
                print('Usage:firewall.py -c <configuration file path>')
                return

	if(parseConfig(args.config) == 0):
		return

	cmd = "sudo tshark -i " + interface + " -f \"dst net not " + ipv4_net + " && dst net not " + ipv6_net
	cmd += " && dst net not 255.255.255.255 && not multicast && !(arp or icmp)\""
	cmd += " -n -T fields -e frame.time -e eth.src -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e dns.qry.name"
	cmd += " -w " + path



	print cmd
	
	signal.signal(signal.SIGINT, sigint_handler)
	
	freq = ast.literal_eval(freq) * 60
	send = threading.Timer(freq, sendFile,[freq])
	send.daemon = True
	send.start()
	'''
	capture = threading.Thread(target = startCapture, args= (cmd,))
	capture.daemon = True
	capture.start()
	'''
	while True:
    		time.sleep(5)


	
if __name__ == '__main__':
	main()                                      
