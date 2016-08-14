#!/usr/bin/python
import sqlite3
import json
import hashlib
import os
import base64
import sys, getopt

db_name = "peer_connection_db"

def main(argv):

	peerId = ''
	try:
		opts, args = getopt.getopt(argv,"h:o:",["getoob=","help="])
	except getopt.GetoptError:
		print 'oobmessage.py -o <peerId>'
		return;
	for opt, arg in opts:
		if opt == '-h':
			print 'oobmessage.py -o <peerId>'
			return;
		elif opt in ("-o", "--getoob"):
			peerId = arg
			print get_oob_message(peerId)
        
 

def ret_obj(noob, hoob, err):
	obj = {}
	obj['noob'] = noob;
	obj['hoob'] = hoob;
	obj['err'] = err;
	return json.dumps(obj)

def get_noob():
	noob = os.urandom(16)
	noob_64 = base64.urlsafe_b64encode(noob +'=' * (4 - (len(noob) % 4)))
	return noob_64

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
        Dirp,PeerInfo, pub_key_serv,nonce_serv, pub_key_peer, nonce_peer  \
        from peers_connected where PeerID ='+'\''+str(peer_id)+'\''	
	
	out = exe_db_query(query)

	if out is None:
		return ret_obj(None, None, "No recored found")

        Dir = int(1) and int(3)	

	hoob_arr = []

	# Add Dir to list
	hoob_arr.append(Dir)
	
	# Add params selected from DB to list
	for item in range (0,len(out)):
		hoob_arr.append(out[item])
	
	# Add noob to list
	hoob_arr.append(noob_b64)

	#convert it to string
	hoob_str = json.dumps(hoob_arr)

	# create hoob by hashing the hoob string
	hoob = hashlib.sha256(hoob_str).hexdigest()	
	# convert it into URL safe Base64 type
	hoob_b64 = base64.urlsafe_b64encode(hoob[0:16] +'=' * (4 - (len(hoob[0:16]) % 4)));

	return ret_obj( hoob_b64 , noob_b64 , None)

def get_oob_message(peer_id):

        # check if peerID is NULL
	if peer_id is None:
		return ret_obj(None, None, "Peer ID NULL")

	#First, get noob
	noob = get_noob()
	
	#Now, generate and return hoob
	return get_hoob(peer_id,noob)

def get_peer_context(peer_id):
	print peer_id

def del_peer_context(peer_id):
	print peer_id

if __name__ == "__main__":
   main(sys.argv[1:])
