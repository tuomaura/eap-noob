## Generating Example Messages

This script creates and outputs example messages using the Curve25519 ECDH test vectors: https://tools.ietf.org/html/rfc7748#section-6.1 (server = Alice, peer = Bob) and the NIST P-256 test vectors: https://tools.ietf.org/html/rfc5903#section-8.1 (server=responder, peer=initiator). This script is used for generating the values used in appendix F (example messages) of the of the draft: https://tools.ietf.org/html/draft-ietf-emu-eap-noob-03#appendix-F. 

The script can be used for verifying other implementations of EAP-NOOB. The beginning of the script contains a section for initializing fields such as the peer and server nonces (which can be imported from other implementations). The script then calculates the corresponding keys, MAC and Hoob values.

The script takes three arguments. The first numeric value (1 or 2) indicates the cryptosuite negotiated during the Initial Exchange. The second numeric value (1 or 2) selects the cryptosuite negotiated during the Reconnect Exchange. The third numeric value (0 or 1) decides if new public keys are exchanged (i.e. forward secrecy is used) during Reconnect Exchange. The third argument only has an affect if the first two arguments are equal. 

### Example Usage

```
$ python3 example_messages.py 1 1 0
$ python3 example_messages.py 1 1 1
$ python3 example_messages.py 1 2 1
```
