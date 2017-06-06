#!/usr/bin/python

import pyinotify
import subprocess
import os
import signal
import os.path
import sys, getopt

class EventHandler(pyinotify.ProcessEvent):
	def process_IN_CLOSE_WRITE(self, event):
		print "MODIFIED:", event.pathname
		reconfigure_hostapd()

def runbash(cmd):
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        out = p.stdout.read().strip()
        return out

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


def start_watching():
	wm = pyinotify.WatchManager()  # Watch Manager
	mask = pyinotify.IN_CLOSE_WRITE  # watched events
	handler = EventHandler()
	notifier = pyinotify.Notifier(wm, handler)
	wdd = wm.add_watch('hostapd.radius_clients', mask, rec=False)
	notifier.loop()

def terminate_hostapd():
        pid = get_pid('hostapd')
        os.kill(int(pid[0]),signal.SIGKILL)

def sigint_handler(signum, frame):
        terminate_hostapd()
        exit(0)

def reconfigure_hostapd():
        pid = get_pid('hostapd')
        print ("Reconfigure Radius Clients")
        os.kill(int(pid[0]),signal.SIGUSR2)

def prepare():
        pid = get_pid('hostapd')
        for item in pid:
                os.kill(int(item),signal.SIGKILL)
        #now start new hostapd

        print ("start hostapd")

        cmd = "./hostapd hostapd.conf -dd"
        subprocess.Popen(cmd,shell=True, stdout=1, stdin=None)

def check_hostapd():
        return os.path.isfile('hostapd')

def main():
	if not(check_hostapd()):
                print ("Hostapd not found")
                return

	prepare()
	start_watching()

if __name__=='__main__':
    main()
