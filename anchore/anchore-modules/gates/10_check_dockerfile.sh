#!/bin/bash

#output policy triggers
# NODOCKERFILE
# NOFROM
# NOTAG
# SUDO

GATENAME="DOCKERFILECHECK"

# source anchore utility shell functions
. `dirname $0`/../shell-utils/anchore_module_utils.sh

# parse the CMDLINE, perform checks and set up useful variable
init_gate_cmdline $@
if [ "$?" != "0" ]; then
    # input didn't parse correctly
    exit 1
fi

for p in $ANCHOREPARAMS
do
    if ( echo $p | grep ALLOWEDPORTS >/dev/null 2>&1 ); then
	NETARG_ALLOW=$p
    fi
    if ( echo $p | grep DENIEDPORTS >/dev/null 2>&1 ); then
	NETARG_DENY=$p
    fi
done

if [ ! -d "$IMGDIR" -o ! -d "$ANALYZERDIR" -o ! -d "$COMPAREDIR" -o -z "$IMGID" -o -z "$OUTPUTDIR" ]; then
    # error input
    echo "ERROR: invalid input, gate cannot execute: $@"
    exit 1
fi

mkdir -p $OUTPUTDIR
OUTPUTFILE="$OUTPUTDIR/${GATENAME}"
echo -n > $OUTPUTFILE

DFILE="$IMGDIR/image_info/Dockerfile"
ISUSER=`cat $IMGDIR/image_info/image.meta | grep usertype | head -n 1 | awk '{print $2}'`
if [ "$ISUSER" != "user" ]; then
    exit 0
fi

if [ ! -d "$IMGDIR" -o ! -f "$DFILE" ]; then
    exit 0
fi

if [ ! -z "$NETARG_ALLOW" -a ! -z "$NETARG_DENY" ]; then
    echo "EXPOSE Both 'ALLOWEDPORTS' and 'DENIEDPORTS' are specified in the parameter list for this image's policy - please specify only one or the other" >> $OUTPUTFILE
    unset NETARG_ALLOW
    unset NETARG_DENY
fi

FLINE=`cat $DFILE | grep -e '^FROM' | head -n 1`
if ( ! echo $FLINE | grep FROM  >/dev/null 2>&1 ); then
    echo "NOFROM No 'FROM' directive in Dockerfile" >> $OUTPUTFILE
elif ( ! echo $FLINE | grep FROM | awk '{print $2}' | grep -v scratch >/dev/null 2>&1); then
    echo "FROMSCRATCH 'FROM' container is 'scratch' - $FLINE" >> $OUTPUTFILE
elif ( ! echo $FLINE | grep FROM | grep ':' | grep -v latest >/dev/null 2>&1); then
    echo "NOTAG 'FROM' container does not specify a non-latest container tag - $FLINE" >> $OUTPUTFILE
fi

if ( grep "sudo" $DFILE >/dev/null 2>&1 ); then
    echo "SUDO Dockerfile contains a 'sudo' command" >> $OUTPUTFILE
fi

if [ ! -z "$NETARG_ALLOW" ]; then
    NPORTS=`echo $NETARG_ALLOW | sed "s/ALLOWEDPORTS=//g"`
    if ( grep "EXPOSE" $DFILE >/dev/null 2>&1 ); then
	if [ "$NPORTS" = "NONE" ]; then
	    echo "EXPOSE Dockerfile exposes network ports that policy file restricts." >> $OUTPUTFILE
	else
	    NPORTSLIST=`echo $NPORTS | sed "s/,/ /g"`
	    for e in `grep EXPOSE $DFILE | head -n 1 | sed "s/EXPOSE//g"`
	    do
		ALLOW="NO"
		for n in $NPORTSLIST
		do
		    if [ "$e" = "$n" ]; then
			ALLOW="YES"
		    fi
		done
		if [ "$ALLOW" = "NO" ]; then
		    echo "EXPOSE Dockerfile exposes port $e which is not in policy file ALLOWEDPORTS list" >> $OUTPUTFILE
		fi
	    done
	fi
    fi
fi
if [ ! -z "$NETARG_DENY" ]; then
    NPORTS=`echo $NETARG_DENY | sed "s/DENIEDPORTS=//g"`
    if ( grep "EXPOSE" $DFILE >/dev/null 2>&1 ); then
	if [ "$NPORTS" = "ALL" ]; then
	    echo "EXPOSE Dockerfile exposes network ports that policy file restricts." >> $OUTPUTFILE
	else
	    NPORTSLIST=`echo $NPORTS | sed "s/,/ /g"`
	    for e in `grep EXPOSE $DFILE | head -n 1 | sed "s/EXPOSE//g"`
	    do
		ALLOW="YES"
		for n in $NPORTSLIST
		do
		    if [ "$e" = "$n" ]; then
			ALLOW="NO"
		    fi
		done
		if [ "$ALLOW" = "NO" ]; then
		    echo "EXPOSE Dockerfile exposes port $e which is in policy file DENIEDPORTS list" >> $OUTPUTFILE
		fi
	    done
	fi
    fi
fi
    
exit 0
