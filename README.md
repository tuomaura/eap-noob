# EAP-NOOB, Nimble out-of-band authentication for EAP
=====================================================

About
--------

This repository is an implementation of EAP-NOOB. It is an EAP method for secure bootstrapping of IoT appliances. The specification for EAP-NOOB can be found at: https://datatracker.ietf.org/doc/draft-aura-eap-noob/?include_text=1.

This implementation consists of three separate applications:

1. hostapd : Contains EAP-NOOB server side implementation (AAA server).

2. wpa_supplicant:  Contains EAP-NOOB peer/supplicant implementation.

3. NodeJS webserver:  Maintains users accounts and provides a front end for the database tracking the IoT appliances being bootstrapped. Out-of-band (OOB) messages encoded as URLs are sent to, or received from this web server. This server is vital for associating the appliance being bootstrapped with a registered user account.

Licensing
------------       
Copyright (c) 2018, Aalto University
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

Neither the name of the Aalto University nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL AALTO UNIVERSITY BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See CONTRIBUTORS for more information.

Setup
-------

	 -------                                --------------                                 ---------
	| WPA_S | ---------------------------- | Access Point | ----------------------------- | Hostapd |
	 -------                                --------------                                 ---------
	   |                                                                                      |
	   |                                                                                      |
	   |                                                                                      |
	   |                                                                                      |
	   |                                       ----------                                 ------------
	   |--------------------------------------|OOB device| ------------------------------| Web server |
                                               ----------                                 ------------


The Access point is a Wi-Fi access point supporting WAP2-enterprise (IEEE 802.1x) authentication. OOB device is a helper device that may be used for delivering the out-of-band (OOB) message. An example OOB device is user's mobile phone.

Dependencies
-----------------  

Following packages have to be installed before compiling the EAP-NOOB code:

1. libssl-dev (minimum version 1.1.1a for elliptic curve X25519).

2. libsqlite3-dev (sqlite3).

3. libjansson-dev (Package for JSON encoding/decoding http://jansson.readthedocs.io/en/2.7/index.html).

4. nodejs-legacy (NodeJS package).

5. npm (node package manager).

Compiling
--------------

hostapd:

1) Move to directory  hostapd-2.6/hostapd.
2) Open build configuration file .config and set CONFIG_DRIVER_WIRED=y and CONFIG_EAP_OOB=y.
3) Run $ make


wpa_supplicant:

1) Move to directory  wpa_supplicant-2.6/wpa_supplicant.
2) Open build configuration file .config and set CONFIG_DRIVER_NL80211=y and CONFIG_EAP_OOB=Y. 	
3) Run $ make


webserver:

1) Move to folder nodejs
2) Run	$ npm install

Ubuntu Compilation
---------------

1) Fetch the tarball: wget https://www.openssl.org/source/openssl-1.1.1a.tar.gz

2) Unpack the tarball with tar -zxf openssl-1.1.1a.tar.gz && cd openssl-1.1.1a

3) Issue the command ./config.

4) Issue the command make (You may need to run sudo apt install make gcc before running this command successfully).

5) Run make test to check for possible errors.

6) Backup current openssl binary: sudo mv /usr/bin/openssl ~/tmp

7) Issue the command sudo make install.

8) Create symbolic link from newly install binary to the default location:

9) sudo ln -s /usr/local/bin/openssl /usr/bin/openssl

10) Run the command sudo ldconfig to update symlinks and rebuild the library cache.

11) sudo apt-get install -y pkg-config libssl-dev libsqlite3-dev libjansson-dev libnl-3-dev libnl-genl-3-dev


Configuration
---------------  

The hostapd (AAA server) and the webserver interact with each other through a shared transactional database. For this interaction to correctly work, they both need to read and write to the same database file peer_connection_db.

hostapd:

At location hostapd-2.6/hostapd edit file eapoob.conf to configure parameters such server URL, Server name etc. For more information on configurable parameters, see Appendix B. Application-specific parameters in the Internet draft.

webserver:

At location nodejs/config edit file "database.js" to fill in the relevant data like server URL and the path to the shared database i.e. absolutes path to database file "peer_connection_db" inside hostapd-2.6/hostapd.

wpa_Supplicant:

At location wpa_supplicant-2.6/wpa_supplicant edit file eapoob.conf to fill in relevant configuration information such as peerinfo etc. For more information on configurable parameters, see Appendix B. Application-specific parameters in the Internet draft.

Execution
------------  

1. hostapd: At location hostapd-2.6/hostapd run the command:

	$  ./hostapd  hostapd.conf

2. webserver: At location nodejs run the command:

	$ node server.js

3. wpa_supplicant: At location wpa_supplicant-2.6/wpa_supplicant run the command:

	$ ./wpa_auto_run.py

Note: Before executing wpa_supplicant, the network manager of the host machine must be stopped. To stop network-manger run the command $ sudo stop network-manger.

A local AAA server can also be used between the Access Point (AP) and the AAA server (hostapd). This would typically happen in enterprise deployments. The local AAA server should be configured to forward all authentication requests containing the Network Access Identifier (NAI) of the form (eap-noob.net) to the hostapd server.  	

Source Files
-------------
Most of the source code for EAP-NOOB can be found at the following files:

hostapd:

1) eap-noob/hostapd-2.6/src/eap_server/eap_server_noob.c

2) eap-noob/hostapd-2.6/src/eap_server/eap_server_noob.h

wpa_supplicant:

1) eap-noob/wpa_supplicant-2.6/src/eap_peer/eap_noob.c

2) eap-noob/wpa_supplicant-2.6/src/eap_peer/eap_noob.h
