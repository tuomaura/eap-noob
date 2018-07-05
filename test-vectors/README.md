## Generating Example Messages

This script creates and outputs example messages using the [Curve25519 ECDH test vectors](https://tools.ietf.org/html/rfc7748#section-6.1) (server = Alice, peer = Bob) and the generated values used in appendix F (example messages) of the [current draft version](https://tools.ietf.org/html/draft-aura-eap-noob-03#appendix-F). Line breaks are for readability only.

The script can be used for verifying other implementations of EAP-NOOB. The beginning of the script contains a section for initialising fields such as the peer and server nonces (which can be imported from other implementations). The script then calculates the corresponding keys, MACs and Hoob values.

### Usage

```
$ python3 example_messages.py
```
