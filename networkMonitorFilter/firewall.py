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

global path

def sendFile(secs):
	print "sent file"
	global path
	if os.path.isfile('send.csv'):
		os.remove('send.csv')
	os.mknod('send.csv')
	cmd = "sudo tshark -T fields -n -r "+ path + " -E separator=/t -e frame.time -e ip.src -e dns.qry.name > send.csv"
	convert = subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)
	convert.wait()
	url = 'https://130.233.193.102:8080/logReport'
	files = {'logFile': open('send.csv', 'rb')}
	r = requests.post(url, files=files,verify=False)
	src = r.json()	
	os.remove('send.csv')
	if src["src"] is not None:
		cmd = "sudo iptables -A FORWARD -s "+src["src"]+" -m state --state NEW,ESTABLISHED,RELATED -j DROP"
		print cmd
		convert = subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)
        	convert.wait() 

	
	send = threading.Timer(secs, sendFile,[secs])
	send.daemon = True
	send.start()

def terminate_tshark(process_name):
        os.system('pkill '+process_name)

def sigint_handler(signum, frame):
        #terminate_tshark("tshark")	
        exit(0)

def startCapture(cmd):	
	subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)
        
def main():
	global path
        parser = argparse.ArgumentParser()
        parser.add_argument('-i', '--interface', dest='interface',help='Name of the interface to monitor')
        parser.add_argument('-p', '--path', dest='path', help='absolute path to target capture file with filename')
        parser.add_argument('-u','--url', dest='url', help='server url to send the captured file')
        parser.add_argument('-t', '--minutes', dest='mins',help='Frequency of sending file to server')
        args = parser.parse_args()

        if (args.interface is None or  args.path is None or args.url is None or args.mins is None):
                print('Usage:firewall.py -i <interface> -p <output file path> -u <server url> -t <frequency of sending in minutes>')
                return
	cmd = "sudo tshark -i " + args.interface + " -f \"dst port 53\" -n -T fields -e frame.time -e ip.src -e dns.qry.name -w " + args.path
	print cmd
	path = args.path
	signal.signal(signal.SIGINT, sigint_handler)
	secs = ast.literal_eval(args.mins) * 60
	send = threading.Timer(secs, sendFile,[secs])
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
