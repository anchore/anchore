#!/bin/bash

ANALYZERNAME="file_list"

# source anchore utility shell functions
. `dirname $0`/../shell-utils/anchore_module_utils.sh

# parse the CMDLINE, perform checks and set up useful variables
init_analyzer_cmdline $ANALYZERNAME $@
if [ "$?" != "0" ]; then
    # input didn't parse correctly
    exit 1
fi

if [ ! -d "$OUTPUTDIR" ]; then
    mkdir -p $OUTPUTDIR
fi

if [ -f "$OUTPUTDIR/files.all" ]; then
    echo "WARN:${0}_MSG:all output files already exist, skipping"
    exit 0
fi

if [ -f "${UNPACKDIR}/squashed.tar" ]; then
    tar tvf $UNPACKDIR/squashed.tar | awk '{print $6, $1}' | sort -k 1 | uniq > $OUTPUTDIR/files.all
fi

exit 0
