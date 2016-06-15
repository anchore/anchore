#!/bin/bash

# this example analyzes the image for all files in /etc that start
# with the letter 'p'

# source anchore utility shell functions
. `dirname $0`/../shell-utils/anchore_module_utils.sh

# parse the CMDLINE, perform checks and set up useful variables
init_analyzer_cmdline "analyzer-example" $@
if [ "$?" != "0" ]; then
    # input didn't parse correctly
    exit 1
fi

# after parsing the cmdline, some useful variables are available
#echo "NAME: $NAME"
#echo "IMGID: $IMGID"
#echo "DATADIR: $DATADIR"
#echo "OUTPUTDIR: $OUTPUTDIR"
#echo "UNPACKDIR: $UNPACKDIR"

# set up some more variables to use for this specific analyzer
IMGROOT="$UNPACKDIR/rootfs"
OUTPUTFILE="$OUTPUTDIR/pfiles"
if [ -f "$OUTPUTFILE" ]; then
    rm -f $OUTPUTFILE
fi
touch $OUTPUTFILE

FOUND="FALSE"
if [ -d "$IMGROOT" ]; then
    # look for pfiles
    for f in `\ls -1ad $IMGROOT/etc/p*`
    do
	echo $f EXISTS >> $OUTPUTFILE
	FOUND="TRUE"
    done
else
    # example of an error condition where analyzer should fail
    echo "ERROR: Cannot location rootfs to search: $IMGROOT"
    exit 1
fi

if [ "$FOUND" == "FALSE" ]; then
    # example of helpful output (can see when running anchore with
    # --debug) but isn't necessarily a failure (just no pfiles)
    echo "RESULT: no pfiles found in image, created output file but should be empty: $OUTPUTFILE"
else
    echo "RESULT: pfiles found in image, review key/val data stored in: $OUTPUTFILE"
fi

# all done!
exit 0
