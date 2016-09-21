#!/bin/bash

# handle the case where 'help' is passed in
if [ "$1" == "help" ]; then
    echo "params: <directory> <directory> ..."
    echo "help: use 'all' to show all files"
    exit 0
fi

# source anchore utility shell functions
. `dirname $0`/../shell-utils/anchore_module_utils.sh

# parse the CMDLINE, perform checks and set up useful variable
init_query_cmdline $@
if [ "$?" != "0" ]; then
    # input didn't parse correctly
    exit 1
fi
PARAMS=($ANCHOREPARAMS)

# run the query
OUTPUT="$OUTPUTDIR/$NAME"

GREPSTR="^PADDING"
for p in ${PARAMS[*]}
do
    if [ "$p" == "all" ]; then
	GREPSTR=".*"
    else
	GREPSTR="${GREPSTR}|^${p}"
    fi
done

PKGFILE="$ANALYZERDIR/file_list/files.all"
if [ -f "$PKGFILE" ]; then
    echo "Image_Id Repo_Tag File Permission"  > $OUTPUT
    if [ -z "$SHORTID" -o -z "$HUMANNAME" ]; then
	export SHORTID="Unknown"
	export HUMANNAME="Unknown"
    fi
 

    cat $PKGFILE | grep -E "($GREPSTR)" | awk -v shortid="$SHORTID" -v humanname="$HUMANNAME" '{print shortid " " humanname " " $0}' >> $OUTPUT

fi

cp $OUTPUT /tmp/jj
# all is well, exit 0
exit 0
