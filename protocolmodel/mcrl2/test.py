#!/usr/bin/python
import os
import re

## Peer variables
peer_vers   = '[1]'
peer_crypts = '[1,2]'
peer_dirs   = '3'

## Server variables
serv_vers   = '[1]'
serv_crypts = '[1,2]'
serv_dirs   = '3'

## Max values
max_peers  = '1'
max_noobs  = '1'
max_nonces = '4'

testfile = './tmp/test.mcf'

tests = [
    ['A Completion Exchange can be succesfully executed',
        [
           # OOB was sent P->S (Dir = 1/3)
            ['> OOB direction: P2S\t',
             '<true* . SERV_STATE(1,S2) . PEER_STATE(1,S1) .\
               true*. SERV_STATE(1,S4) . PEER_STATE(1,S4)>true'
            ],
            # OOB was sent S->P (Dir = 2/3)
            ['> OOB direction: S2P\t',
             '<true* . SERV_STATE(1,S1) . PEER_STATE(1,S2) .\
               true* . SERV_STATE(1,S4) . PEER_STATE(1,S4)>true'
            ]
        ]
    ],
    ['A Reconnect Exchange can be succesfully executed',
        [
            # KeyingMode = 1 (Reconnect Exchange, rekeying without ECDHE)
            ['> KeyingMode: 1\t',
             '<true* . SERV_STATE(1,S4) . PEER_STATE(1,S3) .\
               true* . KEYING_MODE(1,1) . PEER_STATE(1,S4)>true'
            ],
            # Reconnect Exchange, rekeying with ECHDE, no change in cryptosuite
            ['> KeyingMode: 2\t',
             '<true* . SERV_STATE(1,S4) . PEER_STATE(1,S3) .\
               true* . KEYING_MODE(1,2) . PEER_STATE(1,S4)>true'
            ],
            # Reconnect Exchange, rekeying with ECDHE, new cryptosuite
            ['> KeyingMode: 3\t',
             '<true* . SERV_STATE(1,S4) . PEER_STATE(1,S3) .\
               true* . KEYING_MODE(1,3) . PEER_STATE(1,S4)>true'
            ]
        ]
    ]
 ]

errors = [
    ['E1004', 'Unexpected message type',
     '[true* . LOG_ERROR(1, E1004)] false'
    ],
    ['E2002', 'State mismatch, user action required',
     '[true* . LOG_ERROR(1, E2002)] false'
    ],
    ['E3001', 'No mutually supported protocol version',
     '[true* . LOG_ERROR(1, E3001)] false'
    ],
    ['E3002', 'No mutually supported cryptosuite version',
     '[true* . LOG_ERROR(1, E3002)] false'
    ],
    ['E3003', 'No mutually supported OOB direction',
     '[true* . LOG_ERROR(1, E3003)] false'
    ],
    ['E4001', 'HMAC verification failure',
     '[true* . LOG_ERROR(1, E4001)] false'
    ]
]

states = [
    ['1', '1', '<true* . SERV_STATE(1, S1) . PEER_STATE(1, S1)>true'],
    ['1', '2', '<true* . SERV_STATE(1, S1) . PEER_STATE(1, S2)>true'],
    ['2', '1', '<true* . SERV_STATE(1, S2) . PEER_STATE(1, S1)>true'],
    ['4', '3', '<true* . SERV_STATE(1, S4) . PEER_STATE(1, S3)>true'],
    ['4', '4', '<true* . SERV_STATE(1, S4) . PEER_STATE(1, S4)>true']
]


ok = '\x1b[0;30;42m' + '[OK]' + '\x1b[0m'
fail = '\x1b[0;30;41m' + '[FAIL]' + '\x1b[0m'

def setup():
    ## Create a temporary directory
    if not os.path.exists('tmp'):
        os.makedirs('tmp')

    ## Assign values to variables
    with open('eap-noob.mcrl2', 'r') as file:
        model = file.read()

    # Peer variables
    spd = '{}, {}, {}'.format(peer_vers, peer_crypts, peer_dirs)
    model = re.sub('[*], [*], . % @P', spd, model, 1)

    # Server variables
    ssd = '{}, {}, {}'.format(serv_vers, serv_crypts, serv_dirs)
    model = re.sub('[*], [*], . % @S', ssd, model, 1)

    # Max values
    model = re.sub('.; % @M1', '{};'.format(max_peers),  model, 1)
    model = re.sub('.; % @M2', '{};'.format(max_noobs),  model, 1)
    model = re.sub('.; % @M3', '{};'.format(max_nonces), model, 1)

    with open('./tmp/eap-noob.mcrl2', 'w') as file:
        file.write(model)

    ## Copy and run the Makefile
    os.popen('cp Makefile ./tmp/Makefile')
    os.popen('make -C ./tmp/').read()

    print()

def run_tests():
    print ("-- Running tests --")

    output = " {} \t {}"

    for test in tests:
        test_msg = test[0]
        subtests = test[1]

        print ('[' + test_msg + ']')

        for subtest in subtests:
            subtest_msg = subtest[0]
            subtest_mcf = subtest[1]

            with open(testfile,'w') as file:
                file.write(subtest_mcf)

            res = os.popen('lps2pbes -f {} ./tmp/eap-noob.lps | pbes2bool'\
                . format(testfile)).read().strip()

            if res == 'true':
                print (output.format(subtest_msg, ok))
            else:
                print (output.format(subtest_msg, fail))

        print ()

def run_errors():
    print ("-- Testing errors --")

    success = " > {} \t\t\t {}"
    failure = " > {} \t\t\t {} \t [{}]"

    for error in errors:
        error_cde = error[0]
        error_msg = error[1]
        error_mcf = error[2]

        with open(testfile,'w') as file:
            file.write(error_mcf)

        res = os.popen('lps2pbes -f {} ./tmp/eap-noob.lps | pbes2bool'\
            . format(testfile)).read().strip()

        if res == 'true':
            print (success.format(error_cde, ok))
        else:
            print (failure.format(error_cde, fail, error_msg))

    print ()

def run_states():
    print ("-- Testing states --")

    output = " > Server: {} \t Peer: {} \t {}"

    for state in states:
        server_state = state[0]
        peer_state = state[1]
        state_mcf = state[2]

        with open(testfile,'w') as file:
            file.write(state_mcf)

        res = os.popen('lps2pbes -f {} ./tmp/eap-noob.lps | pbes2bool'\
            .format(testfile)).read().strip()

        if res == 'true':
            print (output.format(server_state,peer_state,ok))
        else:
            print (output.format(server_state,peer_state,fail))

def teardown():
    dir = './tmp/'
    files = os.listdir(dir)

    for file in files:
        os.remove(dir + file)

    if not os.listdir(dir):
        os.rmdir('./tmp/')

def main():
    setup()
    run_tests()
    run_errors()
    run_states()
    teardown()

if __name__ == "__main__":
    main()
