#!/bin/bash
tabs 4

echo "--- Running tests -------"
for t in testing/*.mcf
do
    res="$(lps2pbes -f $t eap-noob.lps | pbes2bool)"
    com="$(head -n 1 $t)"
    if [[ $res == true ]]; then
        printf " > ${t#*/}:\t OK \t ${com#*% }\n"
    else
        printf " > ${t#*/}:\t FAIL \t ${com#*% }\n"
    fi
done
echo ""

echo "--- Testing errors ------"
test_error() {
  res="$(lps2pbes -f $1 eap-noob.lps | pbes2bool)"
  com="$(head -n 1 $1)"
  if [[ $res == true ]]; then
      printf " > ${1#*/*/}:\t OK \t ${com#*% }\n"
  else
      # Check if it is possible to recover from the error
      if [ ! -f testing/recovery/${1#*/*/} ]; then
          printf " > ${1#*/*/}:\t FAIL \t ${com#*% }\n"
      else
        res="$(lps2pbes -f testing/recovery/${1#*/*/} eap-noob.lps | pbes2bool)"
        if [[ $res == true ]]; then
            printf " > ${1#*/*/}:\t OK \t ${com#*% }\n"
        else
            printf " > ${1#*/*/}:\t FAIL \t ${com#*% }\n"
        fi
      fi
  fi
}

for t in testing/errors/*.mcf
do
  test_error $t &
done
wait

echo ""

echo "--- Testing states ------"
test_states() {
  SS=${1:21:1}
  PS=${1:23:1}

  RES="$(lts2pbes -f $1 eap-noob.lts | pbes2bool)"
  VAL=$(cat $1 | head -1 | tail -c 12)

  if [[ $RES == false ]]; then
    if [[ $VAL != 'Unreachable' ]]; then
      printf " Server: $SS \t Peer: $PS"
      printf "\t should be reachable\n"
    elif [[ $VAL == 'Unreachable' ]]; then
      printf " Server: $SS \t Peer: $PS"
      printf "\t should not be reachable\n"
    fi
  fi
}

for t in testing/reachability/*.mcf
do
  test_states $t &
done
wait
