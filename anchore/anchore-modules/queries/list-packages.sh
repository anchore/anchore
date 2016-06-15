#!/bin/bash

# handle the case where 'help' is passed in
if [ "$1" == "help" ]; then
    echo "params: <package string> <package string> ..."
    echo "help: search for packages matching <package string>, or use 'all' to show all packages"
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

# perform the query
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

PKGFILE="$ANALYZERDIR/package_list/pkgs.all"
if [ -f "$PKGFILE" ]; then
    echo "ImageID Repo/Tag Package Version"  > $OUTPUT
    cat $PKGFILE | grep -E "($GREPSTR)" | awk -v shortid="$SHORTID" -v humanname="$HUMANNAME" '{print shortid " " humanname " " $0}' >> $OUTPUT
    #while read line
    #do
    #    printf "$SHORTID $HUMANNAME $line\n"
    #done < $PKGFILE | grep -E "$SHORTID $HUMANNAME ($GREPSTR)" >> $OUTPUT
    #cat $PKGFILE | grep -e "$GREPSTR" | sed "s/^/$SHORTID $HUMANNAME /" >> $OUTPUT
fi

# all is good, exit 0
exit 0
