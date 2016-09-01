#!/usr/bin/python3

import random
import sqlite3
import argparse
import os

db_name = 'peer_connection_db'
conn_tbl = 'peer_connections'

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', '--username', dest='username')

	args = parser.parse_args()

	if args.username is None:
		print('Usage: devupdate_simulation.py -u <username>')
		return

	res = os.path.isfile(db_name)
	
	if True != res:
		print ("No database file found")
		return

	con = sqlite3.connect(db_name)

	c = con.cursor()

	c.execute('select count(*) from peers_connected where DevUpdate=0 and username=\''+args.username+'\'')

	num_of_entries = c.fetchone()
	count = num_of_entries[0]
	print(str(count)+' entries found')
	choices = []

	#for row in c.execute('select PeerID from peers_connected where DevUpdate=0 and username=\''+args.username+'\''):
	c.execute('select PeerID from peers_connected where DevUpdate=0 and username=\''+args.username+'\'')
	row_all = c.fetchall()

	for row in row_all:
		if count != 0:
			cmd = 'UPDATE peers_connected SET DevUpdate='+str(count%3)+' where peerID=\''+row[0]+'\''
			count= count-1
			c.execute(cmd)
			con.commit()

	con.close
	print('Done')

if __name__=='__main__':
	main()
