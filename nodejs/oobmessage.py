#!/usr/bin/python
import sqlite3
import json
import hashlib
import os
import base64
import sys, getopt
import argparse
import re
from collections import OrderedDict

realm = None;
noob_conf_file = '../hostapd-2.6/hostapd/eapnoob.conf';
realm_key = 'Realm';

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
        print('Missing arguments')

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

def exe_db_query(query, path, args=None):
    res = os.path.isfile(path)
    if True != res:
        return None

    db_conn = sqlite3.connect(path)
    if db_conn is None:
        return None
    if args is None:
        args = [];
    out = [];
    db_cur = db_conn.cursor();
    db_cur.execute(query, args);
    db_conn.commit();
    out = db_cur.fetchone();
    db_conn.close();
    return out

def print_log(val):
    f1=open('./logfile', 'a+')
    f1.write(val); f1.write("\n");
    f1.close()
    #print(val);

def get_hoob(PeerId, Noob, path, Dir):
    query = 'SELECT Ns, Np, MacInput from EphemeralState where PeerId=?';
    out = exe_db_query(query, path, [PeerId]);
    if out is None:
        print_log("Query returned None, get_hoob");
        return (Noob,None,None);

    Ns_b64 = base64.urlsafe_b64encode(out[0]).decode('ascii').strip('=');
    Np_b64 = base64.urlsafe_b64encode(out[1]).decode('ascii').strip('=');
    hoob_array = json.loads(out[2], object_pairs_hook=OrderedDict);
    hoob_array[0] = int(Dir);
    hoob_array.append(Noob);
    hoob_array[12] = Ns_b64;
    hoob_array[14] = Np_b64;
    hoob_str = json.dumps(hoob_array,separators=(',',':')).encode();
    print_log(hoob_str.decode('utf-8'));
    hoob = hashlib.sha256(hoob_str).digest();
    hoob = base64.urlsafe_b64encode(hoob[0:16]).decode('ascii').strip('=');
    print_log("Hoob " + hoob);
    return ret_obj(Noob,hoob,None);

def get_hoob_comp_res(peerId,noob,path,max_tries, recv_hoob):
    #When hoob noob is received from peer, Dir should 1
    obj = json.loads(get_hoob(peerId, noob, path,1))
    if (obj['hoob'] is not None):
        if(obj['hoob'] == recv_hoob):
            return ret_obj(None, None, None, '8001') # code for success
        else:
            #num_tries += 1
            #db_conn = sqlite3.connect(path)
            # check if DB cannot be accessed
            #if db_conn is None:
            #return ret_obj(None, None, None, '8003') # code for internal error
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
    #When server is generating oobs for server-to-peer, Dir=2
    return get_hoob(peer_id,noob,path,2)

def get_peer_context(peer_id):
    print peer_id

def del_peer_context(peer_id):
    print peer_id

if __name__ == "__main__":
   main(sys.argv[1:])
