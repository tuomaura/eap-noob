#!/bin/bash
tabs 4

echo "--- Running tests -------"
for t in testing/*.mcf
do
    res="$(lps2pbes -f $t eap-noob.lps | pbes2bool)"
    com="$(head -n 1 $t)"
    printf " > ${t#*/}: "
    if [[ $res == true ]]; then
        printf "\t OK \t ${com#*% }\n"
    else
        printf "\t FAIL \t ${com#*% }\n"
    fi
done
echo ""

echo "--- Testing errors ------"
for t in testing/errors/*.mcf
do
    res="$(lps2pbes -f $t eap-noob.lps | pbes2bool)"
    com="$(head -n 1 $t)"
    printf " > ${t#*/*/}: "
    if [[ $res == true ]]; then
        printf "\t OK \t ${com#*% }\n"
    else
        printf "\t FAIL \t ${com#*% }\n"
    fi
done

echo ""

echo "--- Testing states ------"
IMP=$''

for t in testing/reachability/*.mcf
do
    SS=${t:21:1}
    PS=${t:23:1}

    RES="$(lts2pbes -f $t eap-noob.lts | pbes2bool)"
    VAL=$(cat $t | head -1 | tail -c 12)

    if [[ $RES == false ]]; then
      if [[ $VAL != 'Unreachable' ]]; then
        IMP+=" Server: $SS \t Peer: $PS"
        IMP+="\t\t should be reachable\n"
      fi
    else
      if [[ $VAL == 'Unreachable' ]]; then
        IMP+=" Server: $SS \t Peer: $PS"
        IMP+="\t should not be reachable\n"
      fi
    fi
done

# Check if errors were found
if [[ $IMP != '' ]]; then
    echo -e "$IMP"
else
    printf " > Reachable: \t\t OK \t No allowed state combinations are unreachable\n"
    printf " > Unreachable: \t OK \t No forbidden state combinations are reachable\n\n"
fi
