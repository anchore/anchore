#!/bin/bash


function init_query_cmdline {
    export NAME=`echo $0 | awk -F'/' '{print $NF}'`

    if [ -z "$1" ]; then
	return 1
    fi
    if [ "$1" == "help" ]; then
	echo "$NAME called with 'help': module should handle help case prior to calling this routine"
	return 1
    fi
    export IMGFILE="$1"
    export IMAGES=""
    for i in `cat $IMGFILE`
    do
	export IMGID=$i
	export IMAGES="$IMAGES $IMGID"
    done

    if [ -z "$2" ]; then
	return 1
    fi
    export DATADIR="$2"
    export IMGDIR="$2/$IMGID/image_output"
    export ANALYZERDIR="$2/$IMGID/analyzer_output"
    export GATESDIR="$2/$IMGID/gates_output"

    if [ -z "$3" ]; then
	return 1
    fi
    export OUTPUTDIR=$3
    if [ ! -d "$OUTPUTDIR" ]; then
	mkdir -p $OUTPUTDIR
    fi


    for d in $DATADIR $ANALYZERDIR $GATESDIR $OUTPUTDIR
#    for d in $DATADIR $OUTPUTDIR
    do
	if [ ! -d "$d" ]; then
	    echo "Cannot find dir: $d"
	    return 1
	fi
    done

#    if [ ! -f "$IMGDIR/image_info/image.meta" ]; then
#	echo "Cannot find image metadata file: $IMGDIR/image_info/image.meta"
#	return 1
#    fi

#    while read -r key val
#    do
#	key=`echo $key | awk '{print toupper($0)}'`
#	export $key=$val
#    done < $IMGDIR/image_info/image.meta

    anchore toolbox --image ${IMGID} show > ${OUTPUTDIR}/image.env 2>/dev/null
    if [ -f "${OUTPUTDIR}/image.env" -a -s "${OUTPUTDIR}/image.env" ]; then
	#export `cat ${OUTPUTDIR}/image.env`
	source ${OUTPUTDIR}/image.env
    fi
    rm -f ${OUTPUTDIR}/image.env

    export ANCHOREPARAMS="$4 $5 $6 $7 $8 $9 $10"

    return 0
}

function init_gate_cmdline {
    if [ "$2" == "anchore_get_help" ]; then
	# no help available for shell script gates
	exit 0
    fi
    init_query_cmdline $@
    return $?
}

function init_analyzer_cmdline {
    #export NAME=`echo $0 | awk -F'/' '{print $NF}'`
    export NAME=$1

    if [ -z "$2" ]; then
	return 1
    fi
    export IMGID="$2"

    if [ -z "$3" ]; then
	return 1
    fi
    export DATADIR="$3"

    if [ -z "$4" ]; then
	return 1
    fi
    export OUTPUTDIR="$4/analyzer_output/$NAME"
    if [ ! -d "$OUTPUTDIR" ]; then
	mkdir -p $OUTPUTDIR
    fi

    if [ -z "$5" ]; then
	return 1
    fi
    export UNPACKDIR=$5

    for d in $DATADIR $OUTPUTDIR $UNPACKDIR
    do
	if [ ! -d "$d" ]; then
	    echo "Cannot find dir: $d"
	    return 1
	fi
    done

    return 0
}
