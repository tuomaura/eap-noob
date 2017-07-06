#!/usr/bin/python3

import subprocess
import signal
import os
import time
import sqlite3
import json
import sys, getopt
import argparse
#from urlparse import urlparse
from urllib.parse import urlparse
import urllib
import os.path
import re
import _thread
import base64
import hashlib
import threading

from ws4py.client.threadedclient import WebSocketClient
import json
from socket import error as socket_error
import xml.etree.ElementTree as ET
import errno

from selenium import webdriver
#from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys

#chromedriver = "/usr/local/bin/chromedriver"
#os.environ["webdriver.chrome.driver"] = chromedriver
#chrome_options = Options()
#chrome_options.add_argument("--disable-sync")
#chrome_options.add_argument("--no-sandbox")

global conf_file
global driver
global webSocket
interval_threads = []
timeout_threads = []
noob_interval = 30
noob_timeout = 180
db_name = 'peer_connection_db'
conn_tbl = 'connections'
oobs_tbl = "oobs"
config_file = "wpa_supplicant.conf"
target_file = config_file+'.tmp'
noob_conf_file='eapoob.conf'
keyword = 'OobDirs'
oob_out_file = '/tmp/noob_output.txt'
oob_file = 'file.txt'
max_oob_tries = 0
oob_try_keyword = 'OobRetries'
noob_interval_keyword = 'NoobInterval'
noob_timeout_keyword = 'NoobTimeout'
web_socket_keyword = 'EnableWebSocket'

class Client(WebSocketClient):

	def __init__(self, url, peer_id, protocols=None, extensions=None, heartbeat_freq=None,
		ssl_options=None, headers=None):
		super(Client, self).__init__(url, protocols, extensions, heartbeat_freq, ssl_options, headers)
		self.peer_id = peer_id

	def opened(self):
		print("Client is up")
		conf = ET.parse('conf.xml')
		root = conf.getroot()

		device_info = {child.tag: child.text for child in root}
		device_str = json.dumps(device_info)
		self.send(device_str)
		print ("Client is up")

	def closed(self, code, reason=None):
		print ("Closed down", code, reason)

	def received_message(self, m):
		try:
			recv_str = m.data.decode('utf-8')
			msg = json.loads(recv_str)

			if self.validate_msg(msg):
				print (msg)

			if msg['type'] == 'softwareUpdate':
				print("Software Update Received!!")
				resp = {}
				resp['type'] = 'softwareUpdated'
				resp['peerId'] = self.peer_id
				self.send(json.dumps(resp))
			else:
				pass
		except BaseException as e:
			print(e)

	def validate_msg(self, msg):
		return True


def set_max_oob_tries():

	global max_oob_tries
	global noob_interval
	global noob_timeout
	global webSocket
	noob_conf = open(noob_conf_file, 'r')

	for line in noob_conf:
		if '#' != line[0]: 
			if oob_try_keyword in line:
				parts = re.sub('[\s+]', '', line)
				parts = parts.split("#",1)[0]
				parts = parts.split("=",1)[1]
				max_oob_tries = int (parts) if int(parts) > 0 else 5

			elif noob_interval_keyword in line:
				parts = re.sub('[\s+]', '', line)
				parts = parts.split("#",1)[0]
				parts = parts.split("=",1)[1]
				noob_interval = int (parts) if int(parts) > 29 else 1800
			
			elif noob_timeout_keyword in line:
				parts = re.sub('[\s+]', '', line)
				parts = parts.split("#",1)[0]
				parts = parts.split("=",1)[1]
				noob_timeout = int (parts) if int(parts) > 59 else 3600

			elif web_socket_keyword in line:
				parts = re.sub('[\s+]', '', line)
				parts = parts.split("#",1)[0]
				parts = parts.split("=",1)[1]
				webSocket = int (parts) if int(parts) == 0 else 1


def change_config(peerID,realm):

	if peerID is None:
		print ("Peer ID is NULL")
		return

	if os.path.isfile(config_file) is False:
		print ("Config file unavailable")
		return

	old_identity = peerID+'+s1@'+realm
	new_identity = peerID+'+s2@'+realm

	read_conf = open(config_file, 'r')
	write_conf = open(target_file,'w')

	conf_changed =0;

	for line in read_conf:
		if old_identity in line:
			line=line.replace(old_identity,new_identity)
			write_conf.write(line)
			conf_changed = 1
		else:
			write_conf.write(line)

	if conf_changed is 1:
		write_conf.close()
		read_conf.close()
		cmd = 'cp '+target_file+' '+config_file+'  ;  rm -f '+target_file
		runbash(cmd)
		reconfigure_peer()

def exec_query(cmd, qtype):

	retval = 0

	res = os.path.isfile(db_name)

	if True != res:
		#print ("No database file found")
		return 
	# create a DB connection 
	db_conn = sqlite3.connect(db_name)

	# check if DB cannot be accessed
	if db_conn is None:		 
		print ("DB busy")

	db_cur = db_conn.cursor() 	
      
	db_cur.execute(cmd)
	
	if qtype is 1:
		retval = db_cur.fetchone()
	elif qtype is 0:
		db_conn.commit()
	
	db_conn.close()
	return retval

def url_to_db(params):
	
	noob_id = get_noob_id(params['N'][0])
	cmd = 'UPDATE connections SET hint_server ='+'\''+ noob_id+'\''+' ,noob ='+'\''+ params['N'][0]+'\''+' ,hoob =\''+params['H'][0]+'\''+' where PeerID=\''+params['P'][0]+'\'' 
	print (cmd)

	exec_query(cmd,0)

def get_realm(peerId):

	query = 'select realm from connections where PeerID ='+'\''+str(peerId)+'\''

	out = exe_db_query(query)

	return out[0]

# return true when the loop for reading the OOB message needs to be exited
def parse_qr_code(url):
	
	ret_val = 0
	url_comp = urlparse(url);
	
	params = urllib.parse.parse_qs(url_comp.query)

	#print(params)	
	ret_val = check_hoob(params)
	if 1 == ret_val:
		url_to_db(params)
		realm = get_realm(params['P'][0])
		change_config(params['P'][0],realm)	
		print("OOB updated")
		return True

	if  -1 == ret_val: 
		return True

	return False

def read_nfc_card(arg):
	
	no_oob = False

	while not no_oob: 
		no_message = True
		print("In new thread")
		cmd = "./read_through_nfc >"+oob_out_file
		#runbash(cmd)
		subprocess.Popen(cmd,shell=True)

		while no_message:
        		time.sleep(2)
        		oob_output = open(oob_out_file,'r')
        		for line in oob_output:
                		if 'N=' in line and 'H=' in line and 'P=' in line:
                        		no_message = False
        		oob_output.close()

		subprocess.Popen("sudo killall read_through_nfc",shell=True)
		cmd = 'rm -f '+oob_out_file
		runbash(cmd)
		print (line)
		no_oob = parse_qr_code(line)

def read_qr_code(arg):

	no_oob = False

	while not no_oob: 
		no_message = True
		time.sleep(2)
		print("In new thread")
		cmd = "zbarcam >"+oob_out_file
		#runbash(cmd)
		subprocess.Popen(cmd,shell=True)

		while no_message:
        		time.sleep(2)
        		oob_output = open(oob_out_file,'r')
        		for line in oob_output:
                		if 'N=' in line and 'H=' in line and 'P=' in line:
                        		no_message = False
        		oob_output.close()

		subprocess.Popen("sudo killall zbarcam",shell=True)

		cmd = 'rm -f '+oob_out_file
		runbash(cmd)
		print (line)
		no_oob = parse_qr_code(line) 


def exe_db_query(query):
        
        res = os.path.isfile(db_name)   
      
        if True != res:
                return ret_obj(None, None, "No database file found")
        
        # create a DB connection 
        db_conn = sqlite3.connect(db_name)

        # check if DB cannot be accessed
        if db_conn is None:
                return ret_obj(None, None, "DB busy")
      
        out = []        
        db_cur = db_conn.cursor()       
      
        db_cur.execute(query)

        out = db_cur.fetchone()

        db_conn.close()

        return out


def get_hoob(peer_id, noob_b64):

	query = 'select Vers,Verp,PeerID,Csuites,Dirs,ServInfo,Csuitep,\
	Dirp,Realm,PeerInfo, pub_key_serv,nonce_serv, pub_key_peer, nonce_peer  \
	from connections where PeerID ='+'\''+str(peer_id)+'\''

	out = exe_db_query(query)

	if out is None:
		return None

	Dir = int(1) and int(3)
	hoob_arr = []

        # Add Dir to list
	hoob_arr.append(Dir)

        # Add params selected from DB to list
	for item in range (0,len(out)):
		if item == 8 and out[item] == 'eap-noob.net':
			continue;
		hoob_arr.append(out[item])

        # Add noob to list
	hoob_arr.append(noob_b64)

        #convert it to string
	hoob_str = json.dumps(hoob_arr)
	print ("************************" + hoob_str)

	hoob_enc = hoob_str.encode('utf-8')
	hoob = hashlib.sha256(hoob_enc).hexdigest()
	hoob_b64 = base64.urlsafe_b64encode(hoob[0:16].encode('utf-8'))
	#hoob_b64 = hoob_b64.encode('utf-8')
	hoob_b64 = str(hoob_b64, 'utf-8').strip('=')
	print("************************" + hoob_b64)
	return hoob_b64

def get_noob_id(noob_b64):

	noob_id_str = noob_b64+"AFARMERLIVEDUNDERTHEMOUNTAINANDGREWTURNIPSFORALIVING" 	
	noob_id_enc = noob_id_str.encode('utf-8')
	noob_id = hashlib.sha256(noob_id_enc).hexdigest()
	noob_id_b64 = base64.urlsafe_b64encode(noob_id[0:16].encode('utf-8'))
	noob_id_b64 = str(noob_id_b64,'utf-8').strip('=')
	print ("Noob Id is "+noob_id_b64+"\n")
	return noob_id_b64	

def get_noob():
	noob = os.urandom(16)
	#noob_64 = base64.urlsafe_b64encode(noob +'=' * (4 - (len(noob) % 4)))
	noob_64 = base64.urlsafe_b64encode(noob)
	noob_64 = str(noob_64,'utf-8').strip('=')
	return noob_64

def mark_expired(*arg):
	con = sqlite3.connect(db_name)
	c = con.cursor()
	c.execute('UPDATE oobs SET expired = ? WHERE noobId = ?', (1,arg[0]))
	con.commit()
	con.close()

def noob_interval_callback(*arg):
	peer_id = arg[0]
	prev_noob = arg[1]
	con = sqlite3.connect(db_name)
	c = con.cursor()
        # check if peerID is NULL
	if peer_id is None:
		return ret_obj(None, None, "Peer ID NULL")

        #First, get noob
	noob = get_noob()

        #get noob_id
	noob_id =  get_noob_id(noob) 

        #Now, generate and return hoob
	hoob = get_hoob(peer_id,noob)

        #query = 'UPDATE connections SET Noob ='+'\''+ noob+'\''+' ,Hoob =\''+hoob+'\''+',show_OOB =\''+1+'\''+',gen_OOB =\''+0+'\''+' where PeerID=\''+peer_id+'\''
        #exec_query(cmd,0)      

        #c.execute('UPDATE connections SET Noob = ? ,Hoob = ?, hint_server = , show_OOB = ?, gen_OOB = ? WHERE PeerID= ? ',(noob,hoob,noob_id,1,0,peer_id))
	c.execute('UPDATE oobs SET show_oob = ? WHERE noobId= ? AND PeerID = ? ',(0, prev_noob, peer_id))
	c.execute('INSERT INTO oobs(noobId, PeerID, Noob, Hoob, show_oob) values(?,?,?,?,?)',(noob_id, peer_id, noob, hoob, 1))
	con.commit()
	con.close()
	
	t = threading.Timer(noob_interval, noob_interval_callback, [peer_id,noob_id])
	t.start()
	interval_threads.append(t)

	t = threading.Timer(noob_timeout, mark_expired, [noob_id])
	t.start()
	timeout_threads.append(t)


def create_oob(peer_id):
	con = sqlite3.connect(db_name)
	c = con.cursor()
	# check if peerID is NULL
	if peer_id is None:
		return ret_obj(None, None, "Peer ID NULL")

        #First, get noob
	noob = get_noob()

	#get noob_id
	noob_id =  get_noob_id(noob) 

        #Now, generate and return hoob
	hoob = get_hoob(peer_id,noob)

	#query = 'UPDATE connections SET Noob ='+'\''+ noob+'\''+' ,Hoob =\''+hoob+'\''+',show_OOB =\''+1+'\''+',gen_OOB =\''+0+'\''+' where PeerID=\''+peer_id+'\''
	#exec_query(cmd,0)	

	#c.execute('UPDATE connections SET Noob = ? ,Hoob = ?, hint_server = , show_OOB = ?, gen_OOB = ? WHERE PeerID= ? ',(noob,hoob,noob_id,1,0,peer_id))
	c.execute('UPDATE connections SET gen_OOB = ? WHERE PeerID= ? ',(0,peer_id))
	c.execute('INSERT INTO oobs(noobId, PeerID, Noob, Hoob, show_oob) values(?,?,?,?,?)',(noob_id, peer_id, noob, hoob, 1))
	con.commit()
	con.close()

	t = threading.Timer(noob_interval, noob_interval_callback, [peer_id,noob_id])
	t.start()
	interval_threads.append(t)

	t = threading.Timer(noob_timeout, mark_expired, [noob_id])
	t.start()
	timeout_threads.append(t)

def gen_oob():

	con = sqlite3.connect(db_name)
	c = con.cursor()
	for row in c.execute('select PeerID from connections where gen_OOB = 1'):
		#print (row[0] + '\n')
		peer_id = row[0]
		create_oob(peer_id)
	con.close()
	return
	
# 1=success, 0=failure, -1=Max tries reached
def check_hoob(params):

	global max_oob_tries

	if params['P'][0] is not None:
		query = 'select OobRetries from connections where PeerID ='+'\''+str(params['P'][0])+'\''
		out = exe_db_query(query)
		num_tries = out[0]
		
		if(num_tries >= max_oob_tries):
			print("Max oob tries reached")
			return -1

		out = get_hoob(params['P'][0], params['N'][0])

		if (out) == (params['H'][0].strip('\n')):
			return 1

		num_tries += 1
		db_conn = sqlite3.connect(db_name)

                # check if DB cannot be accessed
		if db_conn is None:
			print("Some DB error")
			return 0

		db_cur = db_conn.cursor()
		db_cur.execute('UPDATE connections SET OobRetries = ? WHERE PeerID= ? ',(num_tries,params['P'][0]))
		db_conn.commit()
		db_conn.close()

		print("Hoob mismatch")
		return 0

def update_file(signum, frame):

	#print ('Updating File')
	gen_oob()
	con = sqlite3.connect(db_name)
	c = con.cursor()

	file = open(oob_file, "wb")
	for row in c.execute('select c.ssid,c.ServInfo,o.PeerID,o.Noob,o.Hoob,c.err_code from connections c, oobs o where o.show_OOB = 1 AND c.PeerID = o.PeerID'):
		#print (row[0] + '\n')
		servinfo = json.loads(row[1])
		
		if(row[5]!=0):
			file.write("Error code: "+str(row[5]))
		
		line = (row[0].encode(encoding='UTF-8') + b',' + servinfo['Name'].encode(encoding='UTF-8') + b',' 
		+ servinfo['Url'].encode(encoding='UTF-8')+b'/?P='+row [2].encode(encoding='UTF-8') + 
		b'&N=' + row[3].encode(encoding='UTF-8')+ b'&H=' + row[4].encode(encoding='UTF-8') + b'\n')
		file.write(line)
	file.close()
	con.close()
	return


def runbash(cmd):
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        out = p.stdout.read().strip()
        return out

def check_wpa():
	return os.path.isfile('wpa_supplicant')


def get_pid(arg):
	pid_list = []
	pname = arg.encode(encoding='UTF-8')
	p = runbash(b"ps -A | grep "+pname)
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
	
	print ("start wpa_supplicant")
	cmd = 'rm -f '+config_file+' touch '+config_file+' ; rm -f '+db_name+' ; rm -f '+oob_file

	runbash(cmd)		
	conf_file = open(config_file,'w')
	conf_file.write("ctrl_interface=/var/run/wpa_supplicant \n update_config=1\ndot11RSNAConfigPMKLifetime=1200\n\n")
	conf_file.close()
	cmd = "./wpa_supplicant -i "+iface+" -c wpa_supplicant.conf -O /var/run/wpa_supplicant -d"
	subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)

def network_scan():
	
	while True:
		result = runbash("./wpa_cli scan | grep OK")
		if 'OK' == result.decode():
			print ("scan OK")
			return
	
	
def get_result():
	scan_result = runbash("wpa_cli scan_result | awk '$4 ~ /WPA2-EAP/ {print $3,$5,$1}' | sort $1")
	conf_file = open(config_file,'a')
	token = ''
	ssid_list = []
	token_list = []
	for item in scan_result.decode():
		if '\n' == item:
			token_list.append(token)
			if token_list[1] not in ssid_list:
				ssid_list.append(token_list[1])  
				conf_file.write("network={\n\tssid=\""+token_list[1]+"\"\n\tbssid="+token_list[2]+"\n\tkey_mgmt=WPA-EAP\n\tpairwise=CCMP TKIP"
				"\n\tgroup=CCMP TKIP\n\teap=NOOB\n\tidentity=\"noob@eap-noob.net\"\n}\n\n")
				token = ''
			token_list[:] = []

		elif ' ' == item:
			token_list.append(token)		
			token = ''
		else:
			token += str(item)
	conf_file.close()
	return ssid_list 


def reconfigure_peer():
	pid = get_pid('wpa_supplicant')
	print ("Reconfigure wpa_supplicant")
	os.kill(int(pid[0]),signal.SIGHUP)

	
def check_result():
	res = runbash("./wpa_cli status | grep 'EAP state=SUCCESS'")
	if res == b"EAP state=SUCCESS":
		return True

	return False 

def launch_browser():
	global driver
	#url = "test.html"
	url = "file:///" + os.getcwd() + "/test.html"
	#subprocess.Popen("sudo pkill -9 firefox",shell=True)
	#webbrowser.open(url,new=1,autoraise=True)
	#signal.signal(signal.SIGUSR1, update_file)
	driver = webdriver.Firefox()
	driver.get(url)
	driver.maximize_window()


def get_direction():
        noob_conf = open(noob_conf_file, 'r')

        for line in noob_conf:
                if '#' != line[0] and keyword in line:
                        parts = re.sub('[\s+]', '', line)
                        direction =  (parts[len(keyword)+1])

                        return direction

def terminate_supplicant():
	pid = get_pid('wpa_supplicant')
	os.kill(int(pid[0]),signal.SIGKILL)
	
def sigint_handler(signum, frame):
	terminate_supplicant()			
	exit(0)
	
def check_if_table_exists():
	#cmd = 'SELECT count(*) FROM information_schema.tables WHERE table_name=\''+conn_tbl+'\''
	cmd = 'SELECT name FROM sqlite_master WHERE type=\'table\''
	while True:
		out = exec_query(cmd,1)
		if out is not None and out[0] == conn_tbl:
			return
		time.sleep(3)

def send_via_NFC(path):
	print("Sending through NFC")
	while(False == os.path.isfile(oob_file)):
		pass	
	time.sleep(1)	
	fd = open(oob_file, "r")
	line = fd.readline().split(',')
	fd.close()			
	
	print(line)
	url = line[2].split('&')
	new_url = url[0]+'\\&'+url[1]+'\\&'+url[2]
	cmd = 'python '+path+'examples/beam.py --mode i send link '+ new_url +'" oob URL "'
	print (cmd)
	ret = runbash(cmd)
	print (ret)

def terminate_threads():
	for t in timeout_threads:
		t.cancel()
	for t in interval_threads:
		t.cancel()
	query_str = "DELETE FROM oobs"
	exe_db_query(query_str)	
	print("All timers cancelled")

def test_internet(interface):
	cmd = "ping -c 8 -I " + interface +" 8.8.8.8"
	p = subprocess.Popen(cmd,shell=True)
	status = p.wait()

def web_socket():
	
	query = 'select PeerID, servInfo from connections where state = 4'
	out = exe_db_query(query)
	peer_id = out[0]
	info = json.loads(out[1])
	parts = info ['Url']
	parts = parts.split("://",1)[1]
	ip_addr = parts.split(":",1)[0]

	print(ip_addr)


	print("Web Socket Called")
	#ip_addr = '130.233.193.133'
	url = 'wss://' + ip_addr + ':9000/' + peer_id

	try:
		ws = Client(url, peer_id, protocols=['http-only', 'chat'])
		ws.connect()
		print("logged in")
		ws.run_forever()

	except KeyboardInterrupt:
		print("User exits the program.")

	except socket_error as serr:
		if serr.errno != errno.ECONNREFUSED:
			raise serr
		print (serr)

	except BaseException as e:
		ws.close()


def main():

	
	#cmd = 'sudo systemctl stop NetworkManager.service'   
	#runbash(cmd)
	global driver
	global webSocket


	interface=None
	no_result=0
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--interface', dest='interface',help='Name of the wireless interface')
	parser.add_argument('-p', '--path', dest='path', help='absolute path to home directory of nfcpy')
	parser.add_argument('-n','--nfc', dest='nfc', action='store_const',const='nfc', help='oob message transfer through nfc')
	args = parser.parse_args()

	if args.interface is None:
		print('Usage:wpa_auto_run.py -i <interface> [-p <path>] [-n]')
		return

	if not(check_wpa()):
		print ("WPA_Supplicant not found")
		return

	interface=args.interface

	cmd = 'sudo ifconfig '+interface+' 0.0.0.0 up'   
	runbash(cmd)

	test_internet(interface)

	signal.signal(signal.SIGINT, sigint_handler)
	prepare(interface)
	time.sleep(2)
	network_scan()
	
	while True:
		ssid_list = get_result()
		if len(ssid_list) > 0:
			print (ssid_list)
			break
		time.sleep(2)
	
	reconfigure_peer()	

	direction = get_direction()
	check_if_table_exists()
	
	set_max_oob_tries()
	print("===================================="+str(noob_timeout))
	print("===================================="+ str(noob_interval))
	if direction is '2':
		print("Server to peer direction")
		if args.nfc == 'nfc':
			print("through nfc")
			_thread.start_new_thread(read_nfc_card,(None,))
		else:  
			_thread.start_new_thread(read_qr_code,(None,))
	elif direction is '1':
		print("Peer to server direction")
		query_str = "CREATE TABLE oobs(noobId TEXT PRIMARY KEY, PeerID TEXT, Noob TEXT, Hoob TEXT, show_OOB INTEGER, expired INTEGER)"
		exe_db_query(query_str)
		if args.path is None:
			gen_oob()
			update_file(None,None)
			launch_browser()
		else:
			_thread.start_new_thread(send_via_NFC,(args.path,))
	else:
		print("No direction specified")
		terminate_supplicant()
		exit(0)


	while no_result == 0:
		if check_result():
			no_result =1
		time.sleep(5)
		if direction is '1':	
			gen_oob()
			update_file(None,None)

	print ("***************************************EAP AUTH SUCCESSFUL *****************************************************")	
	
	if direction is '1':
		terminate_threads()
	time.sleep(0.5)
	cmd = 'sudo ifconfig '+interface+' 0.0.0.0 up ; dhclient '+interface   
	#cmd = 'sudo dhclient '+interface   
	runbash(cmd)
	#subprocess.Popen("sudo pkill -9 firefox",shell=True)
	#time.sleep(5)
	#webbrowser.open_new_tab('https://www.youtube.com/watch?v=YlHHTmIkdis')
	if direction is '1':
		driver.close()

	if webSocket == 0:
		url = "https://www.youtube.com/watch?v=YlHHTmIkdis"

		driver = webdriver.Firefox()
		driver.get(url)
		fullscreen = driver.find_elements_by_class_name('ytp-fullscreen-button')[0]
		fullscreen.click()
		while True:
			key = input()
			if key == "r" or key == "R":
				driver.close()
				main()
	else:
		web_socket()

if __name__=='__main__':
    main()
