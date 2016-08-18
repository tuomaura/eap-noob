from urllib.parse import urlparse
import urllib
import sqlite3
import os
import os.path
import subprocess
import re
import _thread
import time

db_name = 'peer_connection_db'
config_file = "wpa_supplicant.conf"
target_file = config_file+'.tmp'
noob_conf_file='eapoob.conf'
keyword = 'Direction'
oob_out_file = '/tmp/noob_output.txt'

def runbash(cmd):
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        out = p.stdout.read().strip()
        return out

def change_config(peerID):

        if peerID is None:
                print ("Peer ID is NULL")
                return

        if os.path.isfile(config_file) is False:
                print ("Config file unavailable")
                return

        old_identity = peerID+'+s1@eap-noob.net'
        new_identity = peerID+'+s2@eap-noob.net'

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

def exec_query(cmd):

	res = os.path.isfile(db_name)

	if True != res:
		print ("No database file found")
		return 
	# create a DB connection 
	db_conn = sqlite3.connect(db_name)

	# check if DB cannot be accessed
	if db_conn is None:		 
		print ("DB busy")

	db_cur = db_conn.cursor() 	
      
	db_cur.execute(cmd)
	db_conn.commit()
	db_conn.close()


def url_to_db(params):
	
	cmd = 'UPDATE connections SET noob ='+'\''+ params['Noob'][0]+'\''+' ,hoob =\''+params['Hoob'][0]+'\''+' where PeerID=\''+params['PeerID'][0]+'\'' 
	print (cmd)

	exec_query(cmd)

def parse_qr_code(url):
	
	url_comp = urlparse(url);
	
	params = urllib.parse.parse_qs(url_comp.query)

	print(params)	
	
	url_to_db(params)

	change_config(params['PeerID'][0])


def read_qr_code(arg):
	no_message = True
	print("In new thread")
	cmd = "zbarcam >"+oob_out_file
	#runbash(cmd)
	subprocess.Popen(cmd,shell=True)

	while no_message:
        	time.sleep(2)
        	print ("File opened")
        	oob_output = open(oob_out_file,'r')
        	for line in oob_output:
                	if 'Noob' in line and 'Hoob' in line and 'PeerID' in line:
                        	no_message = False
        	oob_output.close()
        	print ("File closed")

	subprocess.Popen("sudo killall zbarcam",shell=True)
	cmd = 'rm -f '+oob_out_file
	runbash(cmd)
	print (line)
	parse_qr_code(line) 

def get_direction():
	noob_conf = open(noob_conf_file, 'r')

	for line in noob_conf:
        	if '#' != line[0] and keyword in line:
                	parts = re.sub('[\s+]', '', line)
                	direction =  (parts[len(keyword)+1])

                	return direction

def main():
	direction = get_direction()

	if direction is '2':
		print("Server to peer direction")
		_thread.start_new_thread(read_qr_code,(None,))

	while True:
		pass

if __name__=='__main__':
        main()

