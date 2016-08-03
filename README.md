# EAP-NOOB, Nimble out-of-band authentication for EAP 
=====================================================

About
-------- 

This repository is an implementation of new EAP method named EAP_NOOB. The new method is for secure bootstrapping of IOT appliances. The specification for EAP_NOOB can be found in [this](https://datatracker.ietf.org/doc/draft-aura-eap-noob/?include_text=1) IETF draft.

The implimentation consists of three separate applications.

Hostapd : Contains EAP_NOOB server side implementation and acts as an authenticator for the requesting IOT appliances.

WPA_Supplicant:  Contains EAP_NOOB peer side implementation and contacts an EAP server through an AP to get authenticated. 

Webserver:  It Is for maintaining the account information of all the users under a realm. The out of band message is sent from or gets delivered to this web server. This server is vital for associating the  authenticating device with a user account.

Licensing
------------       
 Copyright (c) 2016, Aalto University 
 All rights reserved. 
 
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: 

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. 

Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution. 

Neither the name of the Aalto University nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission. 
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL AALTO UNIVERSITY BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 
 See CONTRIBUTORS for more information. 

Setup
-------

	 -------                                --------------				                   ---------
	| WPA_S | ---------------------------- | Access Point | ----------------------------- | Hostapd |
	 -------                                --------------                                 ---------
	   |                                                                                      |		           
	   |                                                                                      | 
	   |                                                                                      |		        
	   |                                                                                      |   
	   |			                           ----------                                 ------------
	   |----–---------------------------------|OOB device| ------------------------------| Web server |
		                                       ----------                                 ------------


	1) Access point is a wifi access point configured in WAP2-enterprise mode and OOB device is a device used by the user for delivering out of band message. An example OOB device is user's mobile phone.
	
	2) Webserver and hostapd should run on the same machine.

Dependencies
-----------------  

Following packages have to be installed before compiling any applications from  eapnoobimplimentation.

Openssl-dev (OpenSSL dev library).
libsqlite3-dev (Sqlite3 dev library).
[Jansson](http://jansson.readthedocs.io/en/2.7/index.html).
nodejs-legacy (NodeJS package).
npm (node package manager)

Compiling 
--------------
 
hostapd:

1) Move to directory  hostapd-2.5/hostapd.	
2) Open build configuration file .config and set CONFIG_DRIVER_WIRED=y and CONFIG_EAP_OOB=y.	
3) Now execute  		
  	$ make


wpa_supplicant:

1) Move to directory  wpa_supplicant-2.5/wpa_supplicant.	
2) Open build configuration file .config and set CONFIG_DRIVER_NL80211=y and CONFIG_EAP_OOB=Y. 	
3) Now execute		
	 $ make


Webserver: 

1) Move to folder nodejs	
2) execute 	
    $ npm install	
    
Configuration
---------------  

Hostapd:

At location hostapd-2.5/hostapd edit file eapoob.conf to fill in relevant data like server URL, Server name etc...

Webserver: 

At location nodejs/config edit file "database.js" to fill in the relevant data like server URL and the path to database i.e. absolutes path to database file "peer_connection_db" inside hostapd-2.5/hostapd.

WPA_Supplicant:

At location wpa_supplicant-2.5/wpa_supplicant edit file eapoob.conf to fill in relevant data like peerinfo etc...

Execution
------------  

Hostapd:

At location hostapd-2.5/hostapd  execute
$  ./hostapd  hostapd.conf	

Webserver: 

At location nodejs execute	
$ node server.js	

WPA_Supplicant:

At location wpa_supplicant-2.5/wpa_supplicant execute	
$ ./wpa_auto_run.py	

Note: 
Before executing wpa_supplicant, the network manager of the host machine must be stopped. To stop network-manger execute,
  $ sudo stop network-manger.	

Alternatively a local AAA server can also be used between the Access point and the authenticator (hostapd). The local AAA server will relay the relevant radius message to the authenticator.  	

Source Files
-------------
Files related to EAP-NOOB can be found at the following locations.

Hostapd:

1) eap-noob/hostapd-2.5/src/eap_server/eap_server_noob.c

2) eap-noob/hostapd-2.5/src/eap_server/eap_server_noob.h
 
WPA_supplicant:

1) eap-noob/wpa_supplicant-2.5/src/eap_peer/eap_noob.c

2) eap-noob/wpa_supplicant-2.5/src/eap_peer/eap_noob.h



