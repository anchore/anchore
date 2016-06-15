#!/bin/bash

# handle the case where 'help' is passed in
if [ "$1" == "help" ]; then
    echo "params: <psearchstring>"
    echo "help: pass in a string that starts with 'p' to see if the queries containers have a matching pfile in /etc"
    exit 0
fi

# source anchore utility shell functions
. `dirname $0`/../shell-utils/anchore_module_utils.sh

# parse the CMDLINE, perform checks and set up useful variables
init_query_cmdline $@
if [ "$?" != "0" ]; then
    # input didn't parse correctly
    exit 1
fi
PARAMS=($ANCHOREPARAMS)

# at this point, you have access to:
# $NAME : name for this module
# $IMGID : image ID of image to be queried
# $DATADIR : top level directory of the anchore image data store
# $IMGDIR : location of the files that contain useful image information
# $ANALYZERDIR : location of the files that contain results of the image analysis
# $COMPAREDIR : location of the files that contain comparison results between image and other images in its familytree
# $GATESDIR : location of the results of the latest anchore gate evaulation
# $PARAMS : any extra parameters passed in from the CLI to this module

# run the query

# set the output file name
OUTPUT="$OUTPUTDIR/$NAME"

# queries must always create an output file, and the first line of the
# outputfile must contain space separated list of column header
# names
echo "FullImageID PFileName IsFound"  > $OUTPUT

# this will be the parameter passed to the query 
PSEARCH=${PARAMS[0]}

# perform the search and generate rows of data to the output file
PFILES="$ANALYZERDIR/analyzer-example/pfiles"
if [ -f "$PFILES" ]; then

    # perform your check
    if ( grep -q "$PSEARCH" $PFILES ); then
	ISFOUND="Yes"
    else
	ISFOUND="No"
    fi

    # all additional lines to the outputfile will be read as new rows to present
    echo "$IMGID $PSEARCH $ISFOUND" >> $OUTPUT
fi
echo "RESULT: review query output headers and data rows stored in file: $OUTPUT"

# all is well, exit 0!
exit 0
