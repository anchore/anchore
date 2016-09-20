#!/bin/bash

ANALYZERNAME="file_suids"

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

if [ ! -d "$UNPACKDIR/rootfs/" ]; then
    echo "ERROR:${0}_MSG:Cannot find saved filesystem, skipping analysis"
    exit 1
fi

if [ -f "$OUTPUTDIR/files.suids" ]; then
    echo "WARN:${0}_MSG:all output files already exist, skipping"
    exit 0
fi

touch $UNPACKDIR/suids
if [ -d "$UNPACKDIR/rootfs" ]; then
    (cd $UNPACKDIR/rootfs; find . -user root -perm -4000 | xargs stat -c "%n %a") > $UNPACKDIR/suids 2>/dev/null
fi  
cat $UNPACKDIR/suids | sort | uniq > $OUTPUTDIR/files.suids


