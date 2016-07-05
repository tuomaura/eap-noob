#!/usr/bin/python

import subprocess
import signal
import os
import time

global conf_file

def runbash(cmd):
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        out = p.stdout.read().strip()
        return out

def check_wpa():
	return os.path.isfile('wpa_supplicant')

def get_iface():
	iface = " "
	iface_list = []
	retval = runbash("ifconfig | cut -c1-8 | sort -u | grep 'wlan'")
	for item in retval:
		if item == '\n' or item == '\0':
			iface_list.append(iface)
			iface = " "	
		else:
			iface  = iface+ item
	#return iface_list
	return retval
def start_iface():

	iface = 'wlan'
	num = 0
	iface_list = []

	while len(iface_list) == 0:
		runbash("ifconfig  "+iface+str(num)+"  up")
		iface_list = get_iface()
		print iface_list
		num += 1	
		if num == 3:
			break
	 
	return iface_list

def get_pid(pname):
	pid_list = []
	
	p = runbash("ps -A | grep "+pname)
	if None == p:
		return None

	for line in p.splitlines():
		if pname in line:
			pid = int(line.split(None,1)[0])
			pid_list.append(pid)
	return pid_list

def prepare(iface):
	pid = get_pid('wpa_supplicant')
	for item in pid:
		os.kill(int(item),signal.SIGKILL)
	#now start your own wpa_supplicant
	
	#TODO: remove this when using without conf file
	print "start wpa_supplicant"
	runbash('rm -f eapoob.conf ; touch eapoob.conf')		
	cmd = "./wpa_supplicant -i "+iface+" -c eapoob.conf -O /var/run/wpa_supplicant"	
	subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)

def network_scan():
	#TODO : check if wpa_cli exists or not
	while True:
		result = runbash("./wpa_cli scan | grep OK")
		print result
		if "OK" == result:
			print "scan OK"
			break
	time.sleep(3)
	scan_result = runbash("wpa_cli scan_result | awk '$4 ~ /WPA2-EAP/ {print $3,$5,$1}' | sort $1")
	conf_file = open("eapoob.conf",'w')
	token = ''
	ssid_list = []
	token_list = []
	for item in scan_result:
		if '\n' == item:
 			token_list.append(token)
			if token_list[1] not in ssid_list:
				ssid_list.append(token_list[1])  
				conf_file.write("network={\n\tssid=\""+token_list[1]+"\"\n\tbssid="+token_list[2]+"\n\tkey_mgmt=WPA-EAP\n\tpairwise=CCMP TKIP"
				"\n\tgroup=CCMP TKIP\n\teap=OOB\n\tidentity=\"noob@eap-noob.net\"\n}\n\n")
				token = ''
			token_list[:] = []

		elif ' ' == item:
 			token_list.append(token)		
			token = ''
		else:
			token += item
		
	print ssid_list 
	pid = get_pid('wpa_supplicant')
	print "Reconfigure wpa_supplicant"
	os.kill(int(pid[0]),signal.SIGHUP)
		
	
def main():

	interface_list = []

	if True != check_wpa():
		print "WPA_Supplicant not found"
		return

	interface_list = get_iface()
	if 0 == len(interface_list):
		new_list = start_iface()
		print new_list
		if 0 == len(new_list):
			print "ERROR : No wireless interface"
			return
		else:
			interface_list = new_list
	
	print "Interface found"
	prepare(interface_list)
	time.sleep(1)
        network_scan()

if __name__=='__main__':
        main()

