#!/usr/bin/python

import signal
import os
import time
import sqlite3
import webbrowser
import json

def update_file(signum,frame):
    print ('Updating File')
    
    con = sqlite3.connect('peer_connection_db')

    c = con.cursor()

    file = open("file.txt", "w")

    for row in c.execute('select ssid,ServInfo,PeerID,Noob,Hoob,err_code from connections where show_OOB = 1'):
        print (row[0] + '\n')
 	servinfo = json.loads(row[1])
        if(row[5]!=0):
             file.write("Error code: "+str(row[5]))
        file.write(row[0] + ',' + servinfo['ServName'] + ',' + servinfo['ServUrl'] +'/?PeerId='+row [2] + '&Noob=' + row[3] + '&Hoob=' + row[4] + '\n')

    file.close()
    con.close()
    return

def main():
    
    print ('Main Waiting')
    file = open("file.txt", "w")
    file.close()
    new = 2
    url = "test.html"
    webbrowser.open(url,new=1,autoraise=True)
    signal.signal(signal.SIGUSR1, update_file)
    #signal.signal(signal.SIGUSR2, receive_signal)
    #catchable_sigs = set(signal.__dict__.items()) - {signal.SIGKILL, signal.SIGSTOP}
    #for sig in catchable_sigs:
        #if(sig != signal.SIGUSR1):
            #signal.signal(sig.value, signal.SIG_IGN)
            #print sig

    #print ('My PID is:', os.getpid())

    while True:
        #print ('Waiting...')
        time.sleep(3)

if __name__ == '__main__':
    main()
