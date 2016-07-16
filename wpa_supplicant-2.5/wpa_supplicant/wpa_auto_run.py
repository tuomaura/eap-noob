#!/usr/bin/python

import subprocess
import signal
import os
import time
import webbrowser 
import sqlite3
import json

global conf_file

def update_file(signum, frame):
    print ('Updating File')

    con = sqlite3.connect('peer_connection_db')

    c = con.cursor()

    file = open("file.txt", "w")
    
    for row in c.execute('select ssid,ServInfo,PeerID,Noob,Hoob,err_code from connections where show_OOB = 1'):
        print (row[0] + '\n')
        servinfo = json.loads(row[1])
        if(row[6]!=0):
             file.write("Error code: "+str(row[6]))
        file.write(row[0] + ',' + servinfo['ServName'] + ',' + servinfo['ServUrl'] +'/?PeerId='+row [2] + '&Noob=' + row[3] + '&Hoob=' + row[4] + '\n')
    file.close()
    con.close()
    return


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
	runbash('rm -f wpa_supplicant.conf ; touch wpa_supplicant.conf ')
	runbash('rm -f peer_connection_db')		
	cmd = "./wpa_supplicant -i "+iface+" -c wpa_supplicant.conf -O /var/run/wpa_supplicant "	
	subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)

def network_scan():
	#TODO : check if wpa_cli exists or not
	while True:
		result = runbash("./wpa_cli scan | grep OK")
		print result
		if "OK" == result:
			print "scan OK"
			break
	
	
def get_result():
	scan_result = runbash("wpa_cli scan_result | awk '$4 ~ /WPA2-EAP/ {print $3,$5,$1}' | sort $1")
	conf_file = open("wpa_supplicant.conf",'w')
	conf_file.write("ctrl_interface=/var/run/wpa_supplicant \n update_config=1\n\n")
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
		
	return ssid_list 


def reconfigure_peer():
	pid = get_pid('wpa_supplicant')
	print "Reconfigure wpa_supplicant"
	os.kill(int(pid[0]),signal.SIGHUP)

	
def check_result():
	res = runbash("./wpa_cli status | grep 'EAP state=SUCCESS'")
	
	if res == "EAP state=SUCCESS":
		return True

	return False 

	
def main():
	interface_list = []

	file = open("file.txt", "w")
    	file.close()
    	new = 2
    	url = "test.html"
    	webbrowser.open(url,new=1,autoraise=True)
    	signal.signal(signal.SIGUSR1, update_file)

	if not(check_wpa()):
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
	network_scan()
	
	while True:
		ssid_list = get_result()
		if len(ssid_list) > 0:
			print ssid_listgh
			break
		time.sleep(2)
	
	reconfigure_peer()	

	while True:
		if check_result():
			break
		time.sleep(5)

	print "***************************************EAP AUTH SUCCESSFUL *****************************************************"	
	runbash("dhclient")
	webbrowser.open_new_tab('https://www.youtube.com')
	
if __name__=='__main__':
    main()
