# ProVerif model of the EAP-NOOB protocol

A model of the Nimble out-of-band authentication for EAP (EAP-NOOB). Based on version 03 of the [draft](https://datatracker.ietf.org/doc/draft-ietf-emu-eap-noob/).

## Structure

``` bash
proverif
├── lib
│   └── eap-noob.pvl  # OOB direction 1
├── queries
│   └── eap-noob.pv   # OOB direction 1
├── Makefile
└── README.md
```

## Running Queries

OOB direction 1 (peer-to-server):
``` bash
$ make (default)
```
