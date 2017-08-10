#!/usr/bin/python
import sqlite3
import json
import hashlib
import os
import base64
import sys, getopt
import argparse
import re
#db_name = "peer_connection_db"
realm = None;
noob_conf_file = '../hostapd-2.6/hostapd/eapoob.conf'
realm_key = 'Realm' 

def main(argv):

	peerId=None
	path=None
	noob=None
	max_tries =None

        parser = argparse.ArgumentParser()
        parser.add_argument('-p', '--path', dest='path', help='absolute path to peer_connection_db')
        parser.add_argument('-i','--id', dest='peerId', help='Assigned PeerId of the device')
        parser.add_argument('-n','--gethoob', dest='noob', help='Received noob value')
        parser.add_argument('-t','--MaxOobTries', dest='oobTries', help='Maximum oob tries')
        parser.add_argument('-r','--recvHoob', dest='recvHoob', help='Received Hoob')
        args = parser.parse_args()
	
	peerId = args.peerId
	path = args.path
	noob = args.noob
	recv_hoob = args.recvHoob
	
	if None != args.oobTries:
		max_tries = int(args.oobTries)



	if peerId is not None and path is not None and noob is None:
		print get_oob_message(peerId,path)
	elif peerId is not None and path is not None and noob is not None and recv_hoob is not None and max_tries is not None:
		print get_hoob_comp_res(peerId,noob,path,max_tries,recv_hoob)
 	else:
		print('oobmessage.py -o <peerId> -p <path> [-n <noob>]')


def set_realm():
	
	global realm
	noob_conf = open(noob_conf_file, 'r')

	for line in noob_conf:
        	if '#' != line[0] and realm_key in line:
                	parts = re.sub('[\s+]', '', line)
                	temp = parts.split("#")[0]
                	realm = temp[len(realm_key)+1:]

def ret_obj(noob, hoob, err, result = None):
	obj = {}
	obj['noob'] = noob;
	obj['hoob'] = hoob;
	obj['err'] = err;
	obj['res'] = result

	return json.dumps(obj)

def get_noob():
	noob = os.urandom(16)
	#noob_64 = base64.urlsafe_b64encode(noob +'=' * (4 - (len(noob) % 4)))
	noob_64 = base64.urlsafe_b64encode(noob)
	noob_64 = noob_64.strip('=')
	return noob_64

def exe_db_query(query,path):

	res = os.path.isfile(path)

	if True != res:
		return None
 
	# create a DB connection 
	db_conn = sqlite3.connect(path)

	# check if DB cannot be accessed
	if db_conn is None:		 
		return None

 	out = []	
	db_cur = db_conn.cursor() 	
      
	db_cur.execute(query)
	
	out = db_cur.fetchone()

	db_conn.close()

	return out

def print_log(val):

	f1=open('./logfile', 'a+')
	f1.write(val)
	f1.close()

def get_hoob(peer_id, noob_b64, path):
    query = 'select MacInput from EphemeralState where PeerId ='+'\''+str(peer_id)+'\'';
    out = exe_db_query(query, path)
    if out is None:
        return None

    hoob_array = json.loads(out[0]);
    hoob_array[0] = int(1) and int(3);
    hoob_array.append(noob_b64);
    hoob_array[14] = base64.urlsafe_b64encode(hoob_array[14]).strip('=');
    hoob_array[12] = base64.urlsafe_b64encode(hoob_array[12]).strip('=');

    hoob_str = json.dumps(hoob_array)
    hoob = hashlib.sha256(hoob_str).hexdigest()
    hoob = base64.urlsafe_b64encode(hoob[0:16]).strip('=');
    return ret_obj(noob_b64, hoob, None);

def get_hoob_comp_res(peerId,noob,path,max_tries, recv_hoob):

	#query = 'select OobRetries from peers_connected where PeerId ='+'\''+str(peerId)+'\''
	#out = exe_db_query(query,path)
	#num_tries = int(out[0])

	#if(num_tries >= max_tries):
	#	return ret_obj(None, None, None, '8000') # code for max_tries reached

	obj = json.loads(get_hoob(peerId, noob, path))

	if (obj['hoob'] is not None):
		if(obj['hoob'] == recv_hoob):
			return ret_obj(None, None, None, '8001') # code for success
		else:
			#num_tries += 1
			#db_conn = sqlite3.connect(path)

			# check if DB cannot be accessed
        		#if db_conn is None:
			#	return ret_obj(None, None, None, '8003') # code for internal error

			#db_cur = db_conn.cursor()
			#db_cur.execute('UPDATE peers_connected SET OobRetries = ? WHERE PeerID= ? ',(num_tries,peerId))
        		#db_conn.commit()
        		#db_conn.close()
                		
			return ret_obj(None, None, None, '8002') # code for failure

	else:
		return ret_obj(None, None, None, '8003') # code for internal error
		
			

def get_oob_message(peer_id, path):

        # check if peerID is NULL
	if peer_id is None:
		return ret_obj(None, None, "Peer ID NULL")

	#First, get noob
	noob = get_noob()
	
	#Now, generate and return hoob
	return get_hoob(peer_id,noob,path)

def get_peer_context(peer_id):
	print peer_id

def del_peer_context(peer_id):
	print peer_id

if __name__ == "__main__":
   main(sys.argv[1:])
