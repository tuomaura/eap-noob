#!/usr/bin/python3
import subprocess
import signal
import os
import time
import sqlite3
import json
import argparse
from urllib.parse import urlparse
import urllib
import re
import _thread
import base64
import hashlib
import threading
from collections import OrderedDict
from selenium import webdriver
import json
from socket import error as socket_error
import xml.etree.ElementTree as ET
import errno

global conf_file;
global driver;

max_oob_tries = 0
oob_try_keyword = "OobRetries";
noob_interval_keyword = "NoobInterval";
noob_timeout_keyword = "NoobTimeout";
config_file = "wpa_supplicant.conf";
db_name = "/etc/peer_connection_db";
oob_file = "file.txt";
noob_conf_file = "eapnoob.conf";
keyword = "OobDirs";
timeout_threads = [];


def print_log(val):
    f1=open('./logfile_supplicant', 'a+');
    f1.write(val); f1.write("\n");
    f1.close();
    #print(val);

def runbash(cmd):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE);
    out = p.stdout.read().strip();
    return out;

def launch_browser():
    global driver;
    url = "file:///" + os.getcwd() + "/test.html";
    #Latest Firefox and gecodriver support issues. Disable marionette
    capabilities = webdriver.DesiredCapabilities().FIREFOX;
    capabilities['binary']='/usr/local/bin/geckodriver';
    capabilities['marionette'] = True;
    driver = webdriver.Firefox(capabilities=capabilities);
    driver.get(url);
    driver.maximize_window();

def get_pid(arg):
    pid_list = [];
    pname = arg.encode(encoding='UTF-8');
    p = runbash(b"ps -A | grep "+pname);
    if None == p:
        return None
    for line in p.splitlines():
        if pname in line:
            pid = int(line.split(None,1)[0])
            pid_list.append(pid)
    return pid_list

def terminate_threads():
    for t in timeout_threads:
        t.cancel()
    #for t in interval_threads:
    #    t.cancel()
    print("All timers cancelled")


def get_result():
    scan_result = runbash("wpa_cli scan_result | awk '$4 ~ /WPA2-EAP/ {print $3,$5,$1}' | sort $1")
    conf_file = open(config_file,'a')
    token = ''; ssid_list = []; token_list = [];

    for item in scan_result.decode():	
        if '\n' == item:
            token_list.append(token)
            if token_list[1] not in ssid_list:
                ssid_list.append(token_list[1])
                conf_file.write("network={\n\tssid=\""+token_list[1]+"\"\n\tbssid="+token_list[2]+
                "\n\tkey_mgmt=WPA-EAP\n\tpairwise=CCMP TKIP\n\tgroup=CCMP TKIP\n\teap=NOOB\n\tidentity=\"noob@eap-noob.net\"\n}\n\n");
                token = '';
            token_list[:] = [];
        elif ' ' == item:
            token_list.append(token);
            token = ''
        else:
            token += str(item)
    conf_file.close()
    return ssid_list 

def get_direction():
    noob_conf = open(noob_conf_file, 'r')
    for line in noob_conf:
        if '#' != line[0] and keyword in line:
            parts = re.sub('[\s+]', '', line)
            direction =  (parts[len(keyword)+1])
    return direction

def check_result():
    res = runbash("./wpa_cli status | grep 'EAP state=SUCCESS'")
    if res == b"EAP state=SUCCESS":
        return True
    return False

def network_scan():
    while True:
        result = runbash("./wpa_cli scan | grep OK")
        if 'OK' == result.decode():
            print_log("Network scan OK");
            return

def prepare(iface):
    pid = get_pid('wpa_supplicant')
    for item in pid:
        os.kill(int(item),signal.SIGKILL)
    print_log("Starting wpa_supplicant");
    runbash('rm -f '+config_file+' touch '+config_file+' ; rm -f '+db_name+' ; rm -f '+oob_file);
    conf_file = open(config_file,'w')
    conf_file.write("ctrl_interface=/var/run/wpa_supplicant \n update_config=1\ndot11RSNAConfigPMKLifetime=360\n\n")
    conf_file.close();
    cmd = "./wpa_supplicant -i "+iface+" -c wpa_supplicant.conf -O /var/run/wpa_supplicant -d"
    subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)

def reconfigure_peer():
    print_log("Reconfigure wpa_supplicant");
    pid = get_pid('wpa_supplicant');
    os.kill(int(pid[0]),signal.SIGHUP);

def terminate_supplicant():
    pid = get_pid('wpa_supplicant')
    os.kill(int(pid[0]),signal.SIGKILL)

def sigint_handler(signum, frame):
    print_log("Caught signal {0}".format(signum));
    print("Caught signal {0}".format(signum));
    terminate_supplicant()
    exit(0)

def test_internet(interface):
    cmd = "ping -c 8 -I " + interface +" 8.8.8.8"
    p = subprocess.Popen(cmd,shell=True)
    status = p.wait()

def check_wpa():
    return os.path.isfile('wpa_supplicant')

def set_max_oob_tries():
    global max_oob_tries, noob_interval, noob_timeout;
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


def exe_db_query(query, args=None):
    res = os.path.isfile(db_name)
    if True != res:
        return None

    db_conn = sqlite3.connect(db_name)
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

def update_file():
    file = open(oob_file, "wb")
    #TODO For all rows
    result_serverInfo = exe_db_query("SELECT PeerId, ServerInfo from EphemeralState WHERE PeerState=1");
    if result_serverInfo is None:
        return;
    result_Noob = exe_db_query("SELECT Ssid, PeerId, Noob, Hoob from EphemeralNoob WHERE PeerId = ?",[result_serverInfo[0]]);
    if result_Noob is None:
        return;
    serverInfo = json.loads(result_serverInfo[1]);
    line = result_Noob[0] + "," + serverInfo['Name'] + "," + serverInfo['Url'] + "/?P=" + result_serverInfo[0] + \
            "&N=" + result_Noob[2] + "&H=" + result_Noob[3] + "\n";
    line = bytearray(line.encode('utf-8'));
    file.write(line);
    file.close();
    return

def delete_noob(*args):
    query='DELETE from EphemeralNoob WHERE NoobId=?';
    out = exe_db_query(query, [args[0]]);
    if out is None:
        print_log("Deleting expired Noob failed");

def get_hoob(PeerId, Noob, Dir):
    query = 'SELECT Ns, Np, MacInput from EphemeralState where PeerId=?';
    out = exe_db_query(query, [PeerId]);
    if out is None:
        print_log("Query returned None, get_hoob");
        return None

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
    hoob_b64 = base64.urlsafe_b64encode(hoob[0:16]).decode('ascii').strip('=');
    return hoob_b64;

def get_noob_id(noob_b64):
    noob_id_str = "NoobId"+noob_b64;
    noob_id_enc = noob_id_str.encode('utf-8');
    noob_id = hashlib.sha256(noob_id_enc).digest();
    noob_id_b64 = base64.urlsafe_b64encode(noob_id[0:16]);
    noob_id_b64 = str(noob_id_b64,'utf-8').strip('=');
    return noob_id_b64

def get_noob():
    noob = os.urandom(16);
    noob_64 = base64.urlsafe_b64encode(noob);
    noob_64 = str(noob_64,'utf-8').strip('=');
    return noob_64

def create_oob(PeerId, Ssid):
    if PeerId is None:
        return;
    Noob = get_noob();
    NoobId =  get_noob_id(Noob);
    Hoob = get_hoob(PeerId, Noob, 1);
    print_log("Noob = {0}\nHoob = {1}\n".format(Noob, Hoob));

    query ="INSERT INTO EphemeralNoob(SSid, PeerId, NoobId, Noob, Hoob, sent_time) VALUES(?, ?, ?, ?, ?, ?)";
    args = [Ssid, PeerId, NoobId, Noob, Hoob, 12344];
    ret = exe_db_query(query, args);

    #t = threading.Timer(noob_interval, noob_interval_callback, [PeerId, Ssid, NoobId])
    #t = threading.Timer(noob_interval, create_oob, [PeerId, Ssid])
    #t.start()
    #interval_threads.append(t)

    t = threading.Timer(noob_timeout, delete_noob, [NoobId])
    t.start()
    timeout_threads.append(t)


def gen_oob():
    query="SELECT * from EphemeralState WHERE PeerState=1";
    result = exe_db_query(query);
    if result: #TODO for all rows
       #print_log("Result of query - PeerId {0}, Ssid {1}\n".format(result[1], result[0]));
       create_oob(result[1], result[0]);
    update_file();
    return

def main():
    global driver;
    no_result=0;
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface',help='Name of the wireless interface')
    parser.add_argument('-p', '--path', dest='path', help='absolute path to home directory of nfcpy')
    parser.add_argument('-n','--nfc', dest='nfc', action='store_const',const='nfc', help='oob message transfer through nfc')
    args = parser.parse_args();

    if args.interface is None:
        print('Usage:wpa_auto_run.py -i <interface> [-p <path>] [-n]')
        return

    if not(check_wpa()):
        print_log("WPA_Supplicant not found")
        return

    interface=args.interface
    runbash('sudo ifconfig '+interface+' 0.0.0.0 up');

    #test_internet(interface);
    signal.signal(signal.SIGINT, sigint_handler);
    prepare(interface); time.sleep(2); network_scan();
    while True:
        ssid_list = get_result();
        if len(ssid_list) > 0:
            print(ssid_list)
            break
        time.sleep(2)
    reconfigure_peer();
    direction = get_direction();
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
           # launch_browser()
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
            gen_oob();
        time.sleep(5)

    print_log("EAP AUTH SUCCESSFUL");
    if direction is '1':
        terminate_threads();

    runbash('sudo ifconfig '+interface+' 0.0.0.0 up ; dhclient '+interface);

    #if direction is '1':
     #   driver.close()

    #url = "https://www.youtube.com/watch?v=YlHHTmIkdis"
    #capabilities = webdriver.DesiredCapabilities().FIREFOX;
    #capabilities['binary']='/usr/local/bin/geckodriver';
    #capabilities['marionette'] = True;
    #driver = webdriver.Firefox(capabilities=capabilities);
    #driver.get(url)
    #fullscreen = driver.find_elements_by_class_name('ytp-fullscreen-button')[0]
    #fullscreen.click();

if __name__=='__main__':
    main();
