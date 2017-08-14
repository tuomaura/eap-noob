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
		print_log("DB busy");

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

def exe_db_query(query, args=None):
    res = os.path.isfile(db_name)
    if True != res:
        return None

    db_conn = sqlite3.connect(db_name)
    if db_conn is None:
        return None
    if args is None:
        args = [];
    db_cur = db_conn.cursor();
    db_cur.execute(query);
    out = db_cur.fetchone();
    db_conn.close();
    return out

def print_log(val):
	f1=open('./logfile_supplicant', 'a+');
	f1.write(val);
	f1.write("\n");
	f1.close();

def get_hoob(PeerId, Noob):
    query = 'select Ns, Np, MacInput from EphemeralState where PeerId = ?';
    out = exe_db_query(query, [PeerId]);
    if out is None:
        return None

    hoob_array = json.loads(out[2]);
    hoob_array[0] = int(1) and int(3);
    hoob_array.append(Noob);
    hoob_array[12] = base64.urlsafe_b64encode(out[0]).strip('=');
    hoob_array[14] = base64.urlsafe_b64encode(out[1]).strip('=');
    hoob_str = json.dumps(hoob_array);
    print_log(hoob_str);
    hoob = hashlib.sha256(hoob_str).hexdigest();
    hoob = base64.urlsafe_b64encode(hoob[0:16]).strip('=');
    return hoob;

def get_noob_id(noob_b64):
    print_log("Inside get_noob_id");
    noob_id_str = noob_b64+"AFARMERLIVEDUNDERTHEMOUNTAINANDGREWTURNIPSFORALIVING";
    noob_id_enc = noob_id_str.encode('utf-8')
    noob_id = hashlib.sha256(noob_id_enc).hexdigest()
    print_log("Inside get_noob_id1");
    noob_id_b64 = base64.urlsafe_b64encode(noob_id[0:16].encode('utf-8'))
    print_log("Inside get_noob_id2");
    noob_id_b64 = str(noob_id_b64,'utf-8').strip('=')
    print_log("Noob Id is "+noob_id_b64);
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
	#c.execute('UPDATE oobs SET expired = ? WHERE noobId = ?', (1,arg[0]))
	c.execute('DELETE FROM EphemeralNoob WHERE NoobId=?', arg[0]);
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

def create_oob(PeerId, Ssid):
    print_log("In create_oob");
    if PeerId is None:
        return;
    Noob = get_noob(); print_log("Noob " + str(Noob));
    NoobId =  get_noob_id(noob); print_log("NoobId " + str(NoobId));
    Hoob = get_hoob(PeerId,Noob); print_log("Hoob " + str(Hoob));
    print_log("Noob = {0}\nHoob = {1}\n".format(Noob, Hoob));
    query ='INSERT INTO EphemeralNoob(SSid, PeerId, NoobId, Noob, Hoob, sent_time) VALUES(?, ?, ?, ?, ?, ?)';
    args = [Ssid, PeerId, NoobId, Noob, Hoob, 12344];
    ret = exe_db_query(query, args);
    print_log("Query execution returns {0}".format(str(ret)));

    #t = threading.Timer(noob_interval, noob_interval_callback, [PeerId, Ssid, NoobId])
    t = threading.Timer(noob_interval, create_oob, [PeerId, Ssid])
    t.start()
    interval_threads.append(t)

    t = threading.Timer(noob_timeout, mark_expired, [NoobId])
    t.start()
    timeout_threads.append(t)

def gen_oob():
    query='SELECT * from EphemeralState WHERE PeerState=1';
    result = exe_db_query(query);
    if result:
       print_log("Result of query - PeerId {0}, Ssid {1}\n".format(result[1], result[0]));
       create_oob(result[1], result[0]);
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
    #print_log('Updating OOB File');
    gen_oob();
    file = open(oob_file, "wb")
    result = exe_db_query('SELECT a.ServerInfo, b.Ssid, b.PeerId, b.Noob, b.Hoob from EphemeralState a, EphemeralNoob b WHERE a.PeerId = b.PeerId');
    if result:
        serverInfo = json.loads(row[0]);
        line = (row[1].encode(encoding='UTF-8') + b',' + serverInfo['Name'].encode(encoding='UTF-8') + b','
        + serverInfo['Url'].encode(encoding='UTF-8')+b'/?P='+row [2].encode(encoding='UTF-8') +
        b'&N=' + row[3].encode(encoding='UTF-8')+ b'&H=' + row[4].encode(encoding='UTF-8') + b'\n')
        file.write(line)
    file.close();
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
    print_log("Starting wpa_supplicant")
    runbash('rm -f '+config_file+' touch '+config_file+' ; rm -f '+db_name+' ; rm -f '+oob_file);
    conf_file = open(config_file,'w')
    conf_file.write("ctrl_interface=/var/run/wpa_supplicant \n update_config=1\ndot11RSNAConfigPMKLifetime=1200\n\n")
    conf_file.close()
    cmd = "./wpa_supplicant -i "+iface+" -c wpa_supplicant.conf -O /var/run/wpa_supplicant -d"
    subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)

def network_scan():
    while True:
        result = runbash("./wpa_cli scan | grep OK")
        if 'OK' == result.decode():
            print_log("Network scan OK");
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
    print_log("Reconfigure wpa_supplicant");
    pid = get_pid('wpa_supplicant');
    os.kill(int(pid[0]),signal.SIGHUP);

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
    global driver, webSocket;
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
        print_log("WPA_Supplicant not found")
        return
    interface=args.interface
    runbash('sudo ifconfig '+interface+' 0.0.0.0 up');

    test_internet(interface)
    signal.signal(signal.SIGINT, sigint_handler);
    prepare(interface); time.sleep(2); network_scan();
    while True:
        ssid_list = get_result()
        if len(ssid_list) > 0:
            print (ssid_list)
            break
        time.sleep(2)
    reconfigure_peer();
    direction = get_direction();
    #check_if_table_exists();
    set_max_oob_tries();
    if direction is '2':
        print_log("Server to peer direction")
        if args.nfc == 'nfc':
            _thread.start_new_thread(read_nfc_card,(None,))
        else:
            _thread.start_new_thread(read_qr_code,(None,))
    elif direction is '1':
        print_log("Peer to server direction")
        if args.path is None:
            gen_oob();
            update_file(None,None);
            launch_browser()
        else:
            _thread.start_new_thread(send_via_NFC,(args.path,))
    else:
        print_log("No direction specified")
        terminate_supplicant()
        exit(0)

    while no_result == 0:
        if check_result():
            no_result =1
            time.sleep(5)
        if direction is '1':
            gen_oob()
            update_file(None,None)

    print ("***************************************EAP AUTH SUCCESSFUL *****************************************************");
    if direction is '1':
        terminate_threads()
    time.sleep(0.5)
    runbash('sudo ifconfig '+interface+' 0.0.0.0 up ; dhclient '+interface);
    if direction is '1':
        driver.close()
    url = "https://www.youtube.com/watch?v=YlHHTmIkdis"

    driver = webdriver.Firefox()
    driver.get(url)
    fullscreen = driver.find_elements_by_class_name('ytp-fullscreen-button')[0]
    fullscreen.click()
    if webSocket == 1:
        web_socket()

if __name__=='__main__':
    main()
