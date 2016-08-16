from urllib.parse import urlparse
import urllib
import sqlite3
import os
import os.path
import subprocess

db_name = 'peer_connection_db'
config_file = "wpa_supplicant.conf"
target_file = config_file+'.tmp'

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

def read_qr_code():
	url_file = open('output.txt', 'r')
	
	url = url_file.readline().strip("\n")
	
	url_comp = urlparse(url);
	
	params = urllib.parse.parse_qs(url_comp.query)

	print(params)	
	
	url_to_db(params)

	change_config(params['PeerID'][0])

def main():
	read_qr_code()


if __name__=='__main__':
        main()

