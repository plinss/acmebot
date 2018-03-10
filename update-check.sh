#!/usr/bin/env bash

ACMEBOT=$(which acmebot)

if [ -L ${ACMEBOT} ]; then
    ACMEBOT=$(readlink -f ${ACMEBOT})
fi

DIR=${ACMEBOT%/*}

pushd ${DIR} > /dev/null
/usr/bin/git fetch &> /dev/null
LOG="$(/usr/bin/git log HEAD..origin/master)"
if [[ ${LOG} ]] ; then
    echo "acmebot update available"
    echo
    echo "${LOG}"
    echo
    echo "Run 'cd ${DIR} ; sudo git pull' to update"
    echo
fi
popd > /dev/null
