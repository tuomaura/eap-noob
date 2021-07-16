#!/usr/bin/python
from base64 import urlsafe_b64decode as base64url_decode
from base64 import urlsafe_b64encode as base64url_encode
from collections import OrderedDict
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash as KDF
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from json import loads, dumps
from nacl.public import PrivateKey, PublicKey

## Argument parser
import argparse

parser = argparse.ArgumentParser(description='Generate example messages for\
    EAP-NOOB.')
parser.add_argument('cs1', metavar='c1', type=int,
    help='Cryptosuite for Initial Exchange (1 or 2)')
parser.add_argument('cs2', metavar='c2', type=int,
    help='Cryptosuite for Reconnect Exchange (1 or 2)')
parser.add_argument('pfs', metavar='pfs', type=int,
    help='Forward secrecy (0 or 1)')

args = parser.parse_args()
cs1 = args.cs1
cs2 = args.cs2
pfs = args.pfs

crv1 = "X25519" if cs1 == 1 else "P-256"
crv2 = "X25519" if cs2 == 1 else "P-256"

kty1 = "OKP" if cs1 == 1 else "EC"
kty2 = "OKP" if cs2 == 1 else "EC"

if cs1 == 1:
    print ("Using Curve25519 for Initial Exchange")
elif cs1 == 2:
    print ("Using NIST P-256 for Initial Exchange")
else:
    parser.print_help()
    exit()
if cs2 == 1:
    print ("Using Curve25519 for Reconnect Exchange\n")
elif cs2 == 2:
    print ("Using NIST P-256 for Reconnect Exchange\n")
else:
    parser.print_help()
    exit()
## PeerId
PeerId = '07KRU6OgqX0HIeRFldnbSW'

## Noob (base64 encoded)
Noob_b64 = 'x3JlolaPciK4Wa6XlMJxtQ=='

## Nonces (base64 encoded)
Np_b64 = 'HIvB6g0n2btpxEcU7YXnWB-451ED6L6veQQd6ugiPFU='
Ns_b64 = 'PYO7NVd9Af3BxEri1MI6hL8Ck49YxwCjSRPqlC1SPbw='
Np2_b64 = 'jN0_V4P0JoTqwI9VHHQKd9ozUh7tQdc9ABd-j6oTy_4='
Ns2_b64 = 'RDLahHBlIgnmL_F_xcynrHurLPkCsrp3G3B_S82WUF4='

## NewNAI (was called Realm)
NewNAI = 'noob@example.org'

## Versions
Vers = [1]
Verp = 1

## Cryptosuites
Cryptosuites = [1,2]

## Directions
Dirs = 3
Dirp = 2
Dir = 2

## Hex encoded peer and server keys
# Curve25519 (https://tools.ietf.org/html/rfc7748#section-6.1)
SKs_25519 = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a' # a
SKp_25519 = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb' # b
PKs_25519 = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a' # X25519(a, 9)
PKp_25519 = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f' # X25519(b, 9)
Z_25519 = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'   # K
# Check key derivation
SKs = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(SKs_25519))
SKp = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(SKp_25519))
PKs = SKs.public_key()
PKp = SKp.public_key()
Zs = SKs.exchange(PKp)
Zp = SKp.exchange(PKs)
assert (Zs.hex() == Z_25519 and Zp.hex() == Z_25519)

## Hex encoded peer and server keys
# NIST P-256 (https://tools.ietf.org/html/rfc5903#section-8.1)
SKs_P256 = 'c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433'   # i
SKp_P256 = 'c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53'   # r
PKs_P256_x = 'dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180' # gix
PKs_P256_y = '5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3' # giy
PKp_P256_x = 'd12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63' # grx
PKp_P256_y = '56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab' # gry
Z_P256 = 'd6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de'     # girx
# Check key derivation
SKs = ec.derive_private_key(int(SKs_P256,16), ec.SECP256R1(), default_backend())
SKp = ec.derive_private_key(int(SKp_P256,16), ec.SECP256R1(), default_backend())
PKs = SKs.public_key()
PKp = SKp.public_key()
Zs = SKs.exchange(ec.ECDH(), PKp)
Zp = SKp.exchange(ec.ECDH(), PKs)
assert (Zs.hex() == Z_P256 and Zp.hex() == Z_P256)

# Assign values
Z = Z_25519 if cs1 == 1 else Z_P256
Z2 = Z_25519 if cs2 == 1 else Z_P256

# Encode keys
Z = bytes.fromhex(Z)
Z2 = bytes.fromhex(Z2)

# Base64 encoding
PKp_b64_x = ''
PKs_b64_x = ''
PKp2_b64_x = ''
PKs2_b64_x = ''
PKp_b64_y = ''
PKs_b64_y = ''
PKp2_b64_y = ''
PKs2_b64_y = ''

# Initial Exchange
if cs1 == 1:
    PKp_b64_x = base64url_encode(bytes.fromhex(PKp_25519)).decode().strip('=')
    PKs_b64_x = base64url_encode(bytes.fromhex(PKs_25519)).decode().strip('=')
elif cs1 == 2:
    PKp_b64_x = base64url_encode(bytes.fromhex(PKp_P256_x)).decode().strip('=')
    PKs_b64_x = base64url_encode(bytes.fromhex(PKs_P256_x)).decode().strip('=')
    PKp_b64_y = base64url_encode(bytes.fromhex(PKp_P256_y)).decode().strip('=')
    PKs_b64_y = base64url_encode(bytes.fromhex(PKs_P256_y)).decode().strip('=')
# Reconnect Exchange
if cs2 == 1:
    PKp2_b64_x = base64url_encode(bytes.fromhex(PKp_25519)).decode().strip('=')
    PKs2_b64_x = base64url_encode(bytes.fromhex(PKs_25519)).decode().strip('=')
elif cs2 == 2:
    PKp2_b64_x = base64url_encode(bytes.fromhex(PKp_P256_x)).decode().strip('=')
    PKs2_b64_x = base64url_encode(bytes.fromhex(PKs_P256_x)).decode().strip('=')
    PKp2_b64_y = base64url_encode(bytes.fromhex(PKp_P256_y)).decode().strip('=')
    PKs2_b64_y = base64url_encode(bytes.fromhex(PKs_P256_y)).decode().strip('=')

## Server/Peer Info
ServerInfo = '{"Type":"url_wifi","Name":"Example","Url":"https://noob.example.org/sendOOB"}'
PeerInfo = '{"Type":"wifi","Make":"Acme","Serial":"DU-9999","SSID":"Noob1",\
    "BSSID":"6c:19:8f:83:c2:80"}'

## KeyingMode
# 1 - Reconnect Exchange, rekeying without ECDHE
# 2 - Reconnect Exchange, rekeying with ECHDE, no change in cryptosuite
# 3 - Reconnect Exchange, rekeying with ECDHE, new  cryptosuite negotiated
KeyingMode = 1
if cs1 == cs2 and pfs == True:
    KeyingMode = 2
elif cs1 != cs2:
    KeyingMode = 3

## SleepTime
SleepTime = 60

## Peer and server public keys (jwk formatted)
PKp = loads('{"kty":"","crv":"","x":""}', object_pairs_hook=OrderedDict)
PKs = loads('{"kty":"","crv":"","x":""}', object_pairs_hook=OrderedDict)
PKp2 = loads('{"kty":"","crv":"","x":""}', object_pairs_hook=OrderedDict)
PKs2 = loads('{"kty":"","crv":"","x":""}', object_pairs_hook=OrderedDict)

PKp['kty'] = kty1
PKs['kty'] = kty1
PKp2['kty'] = kty2
PKs2['kty'] = kty2

PKp['crv'] = crv1
PKs['crv'] = crv1
PKp2['crv'] = crv2
PKs2['crv'] = crv2

# Initial Exchange
PKp['x'] = PKp_b64_x
PKs['x'] = PKs_b64_x
if cs1 == 2:
    PKp['y'] = PKp_b64_y
    PKs['y'] = PKs_b64_y

# Reconnect Exchange
if KeyingMode == 1:
    PKp2 = ""
    PKs2 = ""
else:
    PKp2['x'] = PKp2_b64_x
    PKs2['x'] = PKs2_b64_x
    if cs2 == 2:
        PKp2['y'] = PKp2_b64_y
        PKs2['y'] = PKs2_b64_y

## Load peer and server private keys
SK_peer = PrivateKey(bytes.fromhex(SKp_25519 if cs1 == 1 else SKp_P256))
SK_server = PrivateKey(bytes.fromhex(SKs_25519 if cs1 == 1 else SKs_P256))
SK2_peer = PrivateKey(bytes.fromhex(SKp_25519 if cs1 == 1 else SKp_P256))
SK2_server = PrivateKey(bytes.fromhex(SKs_25519 if cs1 == 1 else SKs_P256))

## KDF for completion exchange. Uses NIST Concat KDF.
KDF_input = b'EAP-NOOB' + base64url_decode(Np_b64) + base64url_decode(Ns_b64) +\
    base64url_decode(Noob_b64)
KDF_out = KDF(algorithm=SHA256(), length=320, otherinfo=KDF_input,
    backend=default_backend()).derive(Z)
Kms = KDF_out[224:256]
Kmp = KDF_out[256:288]
Kz = KDF_out[288:320]

# If no new keys are exchanged in the Reconnect Exchange, KDF2 will use the Kz
# from the previous KDF.
Z2 = Kz if KeyingMode == 1 else Z2

# KDF for reconnect exchange. Uses NIST Concat KDF.
KDF2_input = b'EAP-NOOB' + base64url_decode(Np2_b64) + base64url_decode(Ns2_b64)
if KeyingMode == 1:
    KDF2_out = KDF(algorithm=SHA256(), length=288, otherinfo=KDF2_input,
        backend=default_backend()).derive(Z2)
if KeyingMode == 2:
    KDF2_input += Kz
    KDF2_out = KDF(algorithm=SHA256(), length=288, otherinfo=KDF2_input,
        backend=default_backend()).derive(Z2)
if KeyingMode == 3:
    KDF2_input += Kz
    KDF2_out = KDF(algorithm=SHA256(), length=320, otherinfo=KDF2_input,
        backend=default_backend()).derive(Z2)

Kms2 = KDF2_out[224:256]
Kmp2 = KDF2_out[256:288]
Kz2 = KDF2_out[288:320] if KeyingMode == 3 else ''

## Remove trailing '=' from base64 encoded values
Np_b64 = Np_b64.strip('=')
Ns_b64 = Ns_b64.strip('=')
Np2_b64 = Np2_b64.strip('=')
Ns2_b64 = Ns2_b64.strip('=')
Noob_b64 = Noob_b64.strip('=')

## NoobId
NoobId_input = Hash(SHA256(), backend=default_backend())
NoobId_input.update(b'NoobId')
NoobId_input.update(Noob_b64.encode())
NoobId = NoobId_input.finalize()[:16]
NoobId_b64 = base64url_encode(NoobId).decode().strip('=')

## Hoob
Hoob_values = loads('{"Hoob":[]}', object_pairs_hook=OrderedDict)
Hoob_values['Hoob'] = [Dir, Vers, Verp, PeerId, Cryptosuites, Dirs,
    loads(ServerInfo, object_pairs_hook=OrderedDict), cs1, Dirp, NewNAI,
        loads(PeerInfo, object_pairs_hook=OrderedDict), 0, PKs, Ns_b64,
            PKp, Np_b64, Noob_b64]
Hoob_input = Hash(SHA256(), backend=default_backend())
Hoob_input.update(dumps(Hoob_values['Hoob'], separators=(',', ':')).encode())
Hoob = Hoob_input.finalize()[:16]
Hoob_b64 = base64url_encode(Hoob).decode().strip('=')

## OOB
OOB = "P=" + PeerId + "&N=" + Noob_b64 + "&H=" + Hoob_b64

## MACs
MACs_values = loads('{"MACs":[]}', object_pairs_hook=OrderedDict)
MACs_values['MACs'] = [2, Vers, Verp, PeerId, Cryptosuites, Dirs,
    loads(ServerInfo, object_pairs_hook=OrderedDict), cs1, Dirp, NewNAI,
        loads(PeerInfo, object_pairs_hook=OrderedDict), 0, PKs, Ns_b64,
            PKp, Np_b64, Noob_b64]
MACs_input = HMAC(Kms, SHA256(), backend=default_backend())
MACs_input.update(dumps(MACs_values['MACs'], separators=(',', ':')).encode())

## MACp
MACp_values = loads('{"MACp":[]}', object_pairs_hook=OrderedDict)
MACp_values['MACp'] = [1, Vers, Verp, PeerId, Cryptosuites, Dirs,
    loads(ServerInfo, object_pairs_hook=OrderedDict), cs1, Dirp, NewNAI,
        loads(PeerInfo, object_pairs_hook=OrderedDict), 0, PKs, Ns_b64,
            PKp, Np_b64, Noob_b64]
MACp_input = HMAC(Kmp, SHA256(), backend=default_backend())
MACp_input.update(dumps(MACp_values['MACp'], separators=(',', ':')).encode())

## MACs2
MACs2_values = loads('{"MACs2":[]}', object_pairs_hook=OrderedDict)
MACs2_values['MACs2'] = [2, Vers, Verp, PeerId, Cryptosuites, "",
    "", cs2, "", "",
        "", KeyingMode, PKs2, Ns2_b64,
            PKp2, Np2_b64, ""]
MACs2_input = HMAC(Kms2, SHA256(), backend=default_backend())
MACs2_input.update(dumps(MACs2_values['MACs2'], separators=(',', ':')).encode())

## MACp2
MACp2_values = loads('{"MACp2":[]}', object_pairs_hook=OrderedDict)
MACp2_values['MACp2'] = [1, Vers, Verp, PeerId, Cryptosuites, "",
    "", cs2, "", "",
        "", KeyingMode, PKs2, Ns2_b64,
            PKp2, Np2_b64, ""]
MACp2_input = HMAC(Kmp2, SHA256(), backend=default_backend())
MACp2_input.update(dumps(MACp2_values['MACp2'], separators=(',', ':')).encode())

## MAC (base64 encoded)
MACs = base64url_encode(MACs_input.finalize()[:32]).decode().strip('=')
MACp = base64url_encode(MACp_input.finalize()[:32]).decode().strip('=')
MACs2 = base64url_encode(MACs2_input.finalize()[:32]).decode().strip('=')
MACp2 = base64url_encode(MACp2_input.finalize()[:32]).decode().strip('=')

# REQUEST/RESPONSE 1
req1 = loads(
    '{"Type":1}'
    , object_pairs_hook = OrderedDict
)
res1 = loads(
    '{"Type":1, "PeerId":"", "PeerState":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 2
req2 = loads(
    '{"Type":2, "Vers":"", "PeerId":"", "NewNAI":"", "Cryptosuites":"",\
        "Dirs":"", "ServerInfo":""}'
    , object_pairs_hook = OrderedDict
)
res2 = loads(
    '{"Type":2, "Verp":"", "PeerId":"", "Cryptosuitep":"", "Dirp":"",\
        "PeerInfo":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 3
req3 = loads(
    '{"Type":3, "PeerId":"", "PKs":{},\
        "Ns":"", "SleepTime":""}'
    , object_pairs_hook = OrderedDict
)
res3 = loads(
    '{"Type":3, "PeerId":"", "PKp":{},\
        "Np":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 4
req4 = loads(
    '{"Type":4, "PeerId":"", "SleepTime":""}'
    , object_pairs_hook = OrderedDict
)
res4 = loads(
    '{"Type":4, "PeerId":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 5
req5 = loads(
    '{"Type":5, "PeerId":""}'
    , object_pairs_hook = OrderedDict
)
res5 = loads(
    '{"Type":5, "PeerId":"", "NoobId":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 6
req6 = loads(
    '{"Type":6, "PeerId":"", "NoobId":"", "MACs":""}'
    , object_pairs_hook = OrderedDict
)
res6 = loads(
    '{"Type":6, "PeerId":"", "MACp":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 7
req7 = loads(
    '{"Type":7, "Vers":"", "PeerId":"", "Cryptosuites":""}'
    , object_pairs_hook = OrderedDict
)
res7 = loads(
    '{"Type":7, "Verp":"", "PeerId":"", "Cryptosuitep":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 8
req8 = loads( # no new ECDH keys exchanged
   '{"Type":8, "PeerId":"", "KeyingMode":"", "Ns2":""}'
    , object_pairs_hook = OrderedDict
) if KeyingMode == 1 else loads( # new ECDH keys exchanged
   '{"Type":8, "PeerId":"", "KeyingMode":"","PKs2":{}, "Ns2":""}'
    , object_pairs_hook = OrderedDict
)
res8 = loads( # no new ECDH keys exchanged
   '{"Type":8, "PeerId":"", "Np2":""}'
    , object_pairs_hook = OrderedDict
) if KeyingMode == 1 else loads( # new ECDH keys exchanged
   '{"Type":8, "PeerId":"", "PKp2":{},"Np2":""}'
   , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 9
req9 = loads(
    '{"Type":9, "PeerId":"", "MACs2":""}'
    , object_pairs_hook = OrderedDict
)
res9 = loads(
    '{"Type":9, "PeerId":"", "MACp2":""}'
    , object_pairs_hook = OrderedDict
)

## Fill arrays
res1['PeerId'] = PeerId

req2['Vers'] = Vers
req2['PeerId'] = PeerId
req2['NewNAI'] = NewNAI
req2['Cryptosuites'] = Cryptosuites
req2['Dirs'] = Dirs
req2['ServerInfo'] = loads(ServerInfo)

res2['Verp'] = Verp
res2['PeerId'] = PeerId
res2['Cryptosuitep'] = cs1
res2['Dirp'] = Dirp
res2['PeerInfo'] = loads(PeerInfo)

req3['PeerId'] = PeerId
req3['Ns'] = Ns_b64
req3['PKs'] = PKs
req3['SleepTime'] = SleepTime

res3['PeerId'] = PeerId
res3['Np'] = Np_b64
res3['PKp'] = PKp

req4['PeerId'] = PeerId
req4['SleepTime'] = SleepTime

res4['PeerId'] = PeerId

req5['PeerId'] = PeerId

res5['PeerId'] = PeerId
res5['NoobId'] = NoobId_b64

req6['PeerId'] = PeerId
req6['NoobId'] = NoobId_b64
req6['MACs'] = MACs

res6['PeerId'] = PeerId
res6['MACp'] = MACp

req7['Vers'] = Vers
req7['PeerId'] = PeerId
req7['Cryptosuites'] = Cryptosuites

res7['Verp'] = Verp
res7['PeerId'] = PeerId
res7['Cryptosuitep'] = cs2

req8['PeerId'] = PeerId
req8['KeyingMode'] = KeyingMode
req8['PKs2'] = PKs2
req8['Ns2'] = Ns2_b64

res8['PeerId'] = PeerId
res8['Np2'] = Np2_b64
res8['PKp2'] = PKp2

req9['PeerId'] = PeerId
req9['MACs2'] = MACs2

res9['PeerId'] = PeerId
res9['MACp2'] = MACp2

# Initial Exchange
print ("====== Initial Exchange ======")
print("")

print ("Identity response:")
print ("   noob@eap-noob.arpa")
print ("")

print ("EAP request (type 1):")
print ("   " + dumps(req1, separators = (',', ':')))
print ("")

print ("EAP response (type 1):")
print ("   " + '{"Type":1,"PeerState":0}')
print ("")

print ("EAP request (type 2):")
print ("   " + dumps(req2, separators = (',', ':')))
print ("")

print ("EAP response (type 2):")
print ("   " + dumps(res2, separators = (',', ':')))
print ("")

print ("EAP request (type 3):")
print ("   " + dumps(req3, separators = (',', ':')))
print ("")

print ("EAP response (type 3):")
print ("   " + dumps(res3, separators = (',', ':')))
print ("")

# Waiting Exchange
print ("====== Waiting Exchange ======")
print("")

print ("Identity response:")
print ("   noob@example.org")
print ("")

print ("EAP request (type 1):")
print ("   " + dumps(req1, separators = (',', ':')))
print ("")

## Build response type 1
res1['PeerState'] = 1

print ("EAP response (type 1):")
print ("   " + dumps(res1, separators = (',', ':')))
print ("")

print ("EAP request (type 4):")
print ("   " + dumps(req4, separators = (',', ':')))
print ("")

print ("EAP response (type 4):")
print ("   " + dumps(res4, separators = (',', ':')))
print ("")

# OOB Step
print ("====== OOB Step ======")
print ("")

print ("   " + OOB)
print ("")

# Completion Exchange
print ("====== Completion Exchange ======")
print ("")

print ("Identity response:")
print ("   noob@example.org")
print ("")

print ("EAP request (type 1):")
print ("   " + dumps(req1, separators = (',', ':')))
print ("")

## Build response type 1
res1['PeerState'] = 2

print ("EAP response (type 1):")
print ("   " + dumps(res1, separators = (',', ':')))
print ("")

print ("EAP request (type 5):")
print ("   " + dumps(req5, separators = (',', ':')))
print ("")

print ("EAP response (type 5):")
print ("   " + dumps(res5, separators = (',', ':')))
print ("")

print ("EAP request (type 6):")
print ("   " + dumps(req6, separators = (',', ':')))
print ("")

print ("EAP response (type 6):")
print ("   " + dumps(res6, separators = (',', ':')))
print ("")

# Reconnect Exchange
print ("====== Reconnect Exchange (KeyingMode = {}) ======".format(KeyingMode))
print ("")

print ("Identity response:")
print ("   noob@example.org")
print ("")

print ("EAP request (type 1):")
print ("   " + dumps(req1, separators = (',', ':')))
print ("")

## Build response type 1
res1['PeerState'] = 3

print ("EAP response (type 1):")
print ("   " + dumps(res1, separators = (',', ':')))
print ("")

print ("EAP request (type 7):")
print ("   " + dumps(req7, separators = (',', ':')))
print ("")

print ("EAP response (type 7):")
print ("   " + dumps(res7, separators = (',', ':')))
print ("")

print ("EAP request (type 8):")
print ("   " + dumps(req8, separators = (',', ':')))
print ("")

print ("EAP response (type 8):")
print ("   " + dumps(res8, separators = (',', ':')))
print ("")

print ("EAP request (type 9):")
print ("   " + dumps(req9, separators = (',', ':')))
print ("")

print ("EAP response (type 9):")
print ("   " + dumps(res9, separators = (',', ':')))
print ("")

print ("====== Inputs for HOOB, MACs, MACp, MACs2, and MACp2 ======")
print ("")

print ("HOOB input:")
print ("   " + dumps(Hoob_values['Hoob'], separators = (',', ':')))
print ("")

print ("MACs input:")
print ("   " + dumps(MACs_values['MACs'], separators = (',', ':')))
print ("")

print ("MACp input:")
print ("   " + dumps(MACp_values['MACp'], separators = (',', ':')))
print ("")

print ("MACs2 input:")
print ("   " + dumps(MACs2_values['MACs2'], separators = (',', ':')))
print ("")

print ("MACp2 input:")
print ("   " + dumps(MACp2_values['MACp2'], separators = (',', ':')))
print ("")

if KeyingMode == 3:
    print ("====== Keys ======")
    print ("")

    print ("Old Kz:")
    print ("   " + Kz.hex())
    print ("")

    print ("New Kz:")
    print ("   " + Kz2.hex())
    print ("")
