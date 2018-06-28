from base64 import urlsafe_b64decode as base64url_decode
from base64 import urlsafe_b64encode as base64url_encode
from collections import OrderedDict
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash as KDF
from json import loads, dumps
from nacl.bindings import crypto_scalarmult as scalarmult
from nacl.public import PrivateKey, PublicKey
################################################################################
############################### HARDCODED VALUES ###############################
# PeerId
PeerId = '07KRU6OgqX0HIeRFldnbSW'
# Noob - base64 encoded
Noob_b64 = 'x3JlolaPciK4Wa6XlMJxtQ=='
# Nonces - base64 encoded
Np_b64 = 'HIvB6g0n2btpxEcU7YXnWB-451ED6L6veQQd6ugiPFU='
Ns_b64 = 'PYO7NVd9Af3BxEri1MI6hL8Ck49YxwCjSRPqlC1SPbw='
Np2_b64 = 'jN0_V4P0JoTqwI9VHHQKd9ozUh7tQdc9ABd-j6oTy_4='
Ns2_b64 = 'RDLahHBlIgnmL_F_xcynrHurLPkCsrp3G3B_S82WUF4='
# Realm
Realm = 'noob.example.com'
# Versions
Vers = [1]
Verp = 1
# Cryptosuites
Cryptosuites = [1]
Cryptosuitep = 1
# Directions
Dirs = 3
Dirp = 1
Dir = 1
# Hex encoded peer and server public keys
PKp = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'
PKs = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
#PKp2 = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'
#PKs2 = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'

# Hex encoded peer and server private keys
SKp = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
SKs = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
#SKp2 = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
#SKs2 = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'

# Info
ServerInfo = '{"Name":"Example","Url":"https://noob.example.com/sendOOB"}'
PeerInfo = '{"Make":"Acme","Type":"None","Serial":"DU-9999","SSID":"Noob1","BSSID":"6c:19:8f:83:c2:80"}'

# SleepTime
SleepTime = 60


################################################################################
############################## CALCULATED  VALUES ##############################
## Load peer and server public keys
PK_peer = PublicKey(bytes.fromhex(PKp))
PK_server = PublicKey(bytes.fromhex(PKs))
#PK2_peer = PublicKey(bytes.fromhex(PKp))
#PK2_server = PublicKey(bytes.fromhex(PKs))

# Peer and server public keys - base64 encoded
PKp_b64 = base64url_encode(bytes.fromhex(PKp)).decode().strip('=')
PKs_b64 = base64url_encode(bytes.fromhex(PKs)).decode().strip('=')
#PKp2_b64 = base64url_encode(bytes.fromhex(PKp2)).decode().strip('=')
#PKs2_b64 = base64url_encode(bytes.fromhex(PKs2)).decode().strip('=')

# Peer and server public keys - jwk formatted
PKp_full = loads('{"kty":"EC", "crv":"Curve25519", "x":""}')
PKs_full = loads('{"kty":"EC", "crv":"Curve25519", "x":""}')
#PKs2_full = loads('{"kty":"EC", "crv":"Curve25519", "x":""}')
#PKp2_full = loads('{"kty":"EC", "crv":"Curve25519", "x":""}')

PKp_full['x'] = PKp_b64
PKs_full['x'] = PKs_b64
#PKs2_full['x'] = PKs2_b64
#PKp2_full['x'] = PKp2_b64

## Load peer and server private keys
SK_peer = PrivateKey(bytes.fromhex(SKp))
SK_server = PrivateKey(bytes.fromhex(SKs))
#SK2_peer = PrivateKey(bytes.fromhex(SKp2))
#SK2_server = PrivateKey(bytes.fromhex(SKs2))

## Derive shared secret
Z = scalarmult(SK_peer.encode(), PK_server.encode())
assert(Z == scalarmult(SK_server.encode(), PK_peer.encode()))
#Z2 = scalarmult(SK2_peer.encode(), PK2_server.encode())
#assert(Z2 == scalarmult(SK2_server.encode(), PK2_peer.encode()))

## KDF for completion exchange. Uses NIST Concat KDF.
KDF_input = b'EAP-NOOB' + base64url_decode(Np_b64) + base64url_decode(Ns_b64) + base64url_decode(Noob_b64)
KDF_out = KDF(algorithm=SHA256(), length=320, otherinfo=KDF_input, backend=default_backend()).derive(Z)
Kms = KDF_out[224:256]
Kmp = KDF_out[256:288]
Kz = KDF_out[288:320]

# KDF - for reconnect exchange. Uses NIST Concat KDF. This sample script does not exchange new keys in the reconnect
# exchange and uses the Kz from the previous KDF. The script can be modified for using new keys during the reconnect
# exchange by uncommenting the appropriate lines above and using the new Z2 instead of Kz in the KDF 
KDF2_input = b'EAP-NOOB' + base64url_decode(Np2_b64) + base64url_decode(Ns2_b64)
KDF2_out = KDF(algorithm=SHA256(), length=288, otherinfo=KDF2_input, backend=default_backend()).derive(Kz)
Kms2 = KDF2_out[224:256]
Kmp2 = KDF2_out[256:288]

# Remove trailing '=' from base64 encoded values
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
Hoob_values['Hoob'] = [Dir, Vers, Verp, PeerId, Cryptosuites, Dirs, loads(ServerInfo), Cryptosuitep, Dirp, Realm, loads(PeerInfo), PKs_full, Ns_b64, PKp_full, Np_b64, Noob_b64]
Hoob_input = Hash(SHA256(), backend=default_backend())
Hoob_input.update(dumps(Hoob_values['Hoob'], separators=(',', ':')).encode())
Hoob = Hoob_input.finalize()[:16]
Hoob_b64 = base64url_encode(Hoob).decode().strip('=')

## OOB
OOB = "P=" + PeerId + "&N=" + Noob_b64 + "&H=" + Hoob_b64

## MACs
MACs_values = loads('{"MACs":[]}', object_pairs_hook=OrderedDict)
MACs_values['MACs'] = [2, Vers, Verp, PeerId, Cryptosuites, Dirs, loads(ServerInfo), Cryptosuitep, Dirp, Realm, loads(PeerInfo), PKs_full, Ns_b64, PKp_full, Np_b64, Noob_b64]
MACs_input = HMAC(Kms, SHA256(), backend=default_backend())
MACs_input.update(dumps(MACs_values['MACs'], separators=(',', ':')).encode())

# MACp
MACp_values = loads('{"MACp":[]}', object_pairs_hook=OrderedDict)
MACp_values['MACp'] = [1, Vers, Verp, PeerId, Cryptosuites, Dirs, loads(ServerInfo), Cryptosuitep, Dirp, Realm, loads(PeerInfo), PKs_full, Ns_b64, PKp_full, Np_b64, Noob_b64]
MACp_input = HMAC(Kmp, SHA256(), backend=default_backend())
MACp_input.update(dumps(MACp_values['MACp'], separators=(',', ':')).encode())

# MACs2
MACs2_values = loads('{"MACs2":[]}', object_pairs_hook=OrderedDict)
MACs2_values['MACs2'] = [2, Vers, Verp, PeerId, Cryptosuites, "", loads(ServerInfo), Cryptosuitep, "", Realm, loads(PeerInfo), "", Ns2_b64, "", Np2_b64, ""]
MACs2_input = HMAC(Kms2, SHA256(), backend=default_backend())
MACs2_input.update(dumps(MACs2_values['MACs2'], separators=(',', ':')).encode())

# MACp2
MACp2_values = loads('{"MACp2":[]}', object_pairs_hook=OrderedDict)
MACp2_values['MACp2'] = [1, Vers, Verp, PeerId, Cryptosuites, "", loads(ServerInfo), Cryptosuitep, "", Realm, loads(PeerInfo), "", Ns2_b64, "", Np2_b64, ""]
MACp2_input = HMAC(Kmp2, SHA256(), backend=default_backend())
MACp2_input.update(dumps(MACp2_values['MACp2'], separators=(',', ':')).encode())
# MAC - base64 encoded
MACs = base64url_encode(MACs_input.finalize()[:32]).decode().strip('=')
MACp = base64url_encode(MACp_input.finalize()[:32]).decode().strip('=')
MACs2 = base64url_encode(MACs2_input.finalize()[:32]).decode().strip('=')
MACp2 = base64url_encode(MACp2_input.finalize()[:32]).decode().strip('=')

################################################################################
############################## CREATE JSON ARRAYS ##############################
# REQUEST/RESPONSE 1
req1 = loads(
    '{"Type":1, "Vers":"", "PeerId":"", "Realm":"", "Cryptosuites":"", "Dirs":"", "ServerInfo":""}'
    , object_pairs_hook = OrderedDict
)
res1 = loads(
    '{"Type":1, "Verp":"", "PeerId":"", "Cryptosuitep":"", "Dirp":"", "PeerInfo":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 2
req2 = loads(
    '{"Type":2, "PeerId":"", "PKs":{"kty":"EC", "crv":"Curve25519", "x":""}, "Ns":"", "SleepTime":""}'
    , object_pairs_hook = OrderedDict
)
res2 = loads(
    '{"Type":2, "PeerId":"", "PKp":{"kty":"EC", "crv":"Curve25519", "x":""}, "Np":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 3
req3 = loads(
    '{"Type":3, "PeerId":"", "SleepTime":""}'
    , object_pairs_hook = OrderedDict
)
res3 = loads(
    '{"Type":3, "PeerId":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 4
req4 = loads(
    '{"Type":4, "PeerId":"", "NoobId":"", "MACs":""}'
    , object_pairs_hook = OrderedDict
)
res4 = loads(
    '{"Type":4, "PeerId":"", "MACp":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 5
req5 = loads(
    '{"Type":5, "Vers":"", "PeerId":"", "Cryptosuites":"", "Realm":"", "ServerInfo":""}'
    , object_pairs_hook = OrderedDict
)
res5 = loads(
    '{"Type":5, "Verp":"", "PeerId":"", "Cryptosuitep":"", "PeerInfo":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 6 no new ECDH keys exchanged
req6 = loads(
    '{"Type":6, "PeerId":"", "Ns2":""}'
    , object_pairs_hook = OrderedDict
)
res6 = loads(
    '{"Type":6, "PeerId":"", "Np2":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 6 new ECDH keys exchanged
#req6 = loads(
#    '{"Type":6, "PeerId":"", "PKs2":{"kty":"EC", "crv":"Curve25519", "x":""}, "Ns2":""}'
#    , object_pairs_hook = OrderedDict
#)
#res6 = loads(
#    '{"Type":6, "PeerId":"", "PKp2":{"kty":"EC", "crv":"Curve25519", "x":""}, "Np2":""}'
#    , object_pairs_hook = OrderedDict
#)


# REQUEST/RESPONSE 7
req7 = loads(
    '{"Type":7, "PeerId":"", "MACs2":""}'
    , object_pairs_hook = OrderedDict
)
res7 = loads(
    '{"Type":7, "PeerId":"", "MACp2":""}'
    , object_pairs_hook = OrderedDict
)

# REQUEST/RESPONSE 8
req8 = loads(
    '{"Type":8, "PeerId":""}'
    , object_pairs_hook = OrderedDict
)
res8 = loads(
    '{"Type":8, "PeerId":"", "NoobId":""}'
    , object_pairs_hook = OrderedDict
)

## Fill arrays
req1['Vers'] = Vers
req1['PeerId'] = PeerId
req1['Realm'] = Realm
req1['Cryptosuites'] = Cryptosuites
req1['Dirs'] = Dirs
req1['ServerInfo'] = loads(ServerInfo)

res1['Verp'] = Verp
res1['PeerId'] = PeerId
res1['Cryptosuitep'] = Cryptosuitep
res1['Dirp'] = Dirp
res1['PeerInfo'] = loads(PeerInfo)

req2['PeerId'] = PeerId
req2['Ns'] = Ns_b64
req2['PKs']['x'] = PKs_b64
req2['SleepTime'] = SleepTime

res2['PeerId'] = PeerId
res2['Np'] = Np_b64
res2['PKp']['x'] = PKp_b64

req3['PeerId'] = PeerId
req3['SleepTime'] = SleepTime

res3['PeerId'] = PeerId

req4['PeerId'] = PeerId
req4['NoobId'] = NoobId_b64
req4['MACs'] = MACs

res4['PeerId'] = PeerId
res4['MACp'] = MACp

req5['Vers'] = Vers
req5['PeerId'] = PeerId
req5['Cryptosuites'] = Cryptosuites
req5['Realm'] = Realm
req5['ServerInfo'] = loads(ServerInfo)

res5['Verp'] = Verp
res5['PeerId'] = PeerId
res5['Cryptosuitep'] = Cryptosuitep
res5['PeerInfo'] = loads(PeerInfo)

req6['PeerId'] = PeerId
#req6['PKs2']['x'] = PKs2_b64
req6['Ns2'] = Ns2_b64

res6['PeerId'] = PeerId
#res6['PKp2']['x'] = PKp2_b64
res6['Np2'] = Np2_b64

req7['PeerId'] = PeerId
req7['MACs2'] = MACs2

res7['PeerId'] = PeerId
res7['MACp2'] = MACp2

req8['PeerId'] = PeerId

res8['PeerId'] = PeerId
res8['NoobId'] = NoobId_b64

################################################################################
############################### PRINT EVERYTHING ###############################
# Initial Exchange
print ("====== Initial Exchange ======")
print("")

print ("Identity response:")
print ("   noob@eap-noob.net")
print ("")

print ("EAP request (type 1):")
print ("   " + dumps(req1, separators = (',', ':')))
print ("")

print ("EAP response (type 1):")
print ("   " + dumps(res1, separators = (',', ':')))
print ("")

print ("EAP request (type 2):")
print ("   " + dumps(req2, separators = (',', ':')))
print ("")

print ("EAP response (type 2):")
print ("   " + dumps(res2, separators = (',', ':')))
print ("")

# Waiting Exchange
print ("====== Waiting Exchange ======")
print("")

print ("Identity response:")
print ("   " + PeerId + "+s1@noob.example.com")
print("")

print ("EAP request (type 3):")
print ("   " + dumps(req3, separators = (',', ':')))
print ("")

print ("EAP response (type 3):")
print ("   " + dumps(res3, separators = (',', ':')))
print ("")

# OOB Step
print ("====== OOB Step ======")
print ("")

print ("Identity response:")
print ("   " + OOB)
print ("")

# Completion Exchange
print ("====== Completion Exchange ======")
print ("")

print ("Identity response:")
print ("   " + PeerId + "+s2@noob.example.com")
print ("")

print ("EAP request (type 8):")
print ("   " + dumps(req8, separators = (',', ':')))
print ("")

print ("EAP response (type 8):")
print ("   " + dumps(res8, separators = (',', ':')))
print ("")

print ("EAP request (type 4):")
print ("   " + dumps(req4, separators = (',', ':')))
print ("")

print ("EAP response (type 4):")
print ("   " + dumps(res4, separators = (',', ':')))
print ("")

# Reconnect Exchange
print ("====== Reconnect Exchange ======")
print ("")

print ("Identity response:")
print ("   " + PeerId + "+s3@noob.example.com")
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

print ("EAP request (type 7):")
print ("   " + dumps(req7, separators = (',', ':')))
print ("")

print ("EAP response (type 7):")
print ("   " + dumps(res7, separators = (',', ':')))
print ("")
################################################################################
