#!/bin/bash

if ( ! anchore --help >/dev/null 2>&1 ); then
    echo "must install anchore first"
    exit 1
fi

if ( ! help2man --help >/dev/null 2>&1 ); then
    echo "must install help2man first"
    exit 1
fi

if [ ! -d "../../doc/man/" ]; then
    echo "cannot find output dir ../../doc/man/, please cd to anchore/scripts/release and run this command"
    exit 1
fi

VERSIONSTRING=`anchore --version 2>&1`
VERSION=`echo $VERSIONSTRING | awk '{print $3}'`
help2man -N --no-discard-stderr -o ../../docs/man/anchore.1 anchore
SUBCOMMANDS=`anchore  | grep 'Commands:' -A100 | grep -v 'Commands:' | awk '{print $1}'`
for S in ${SUBCOMMANDS}
do
    help2man -N --no-discard-stderr --version-string "$VERSIONSTRING" -o ../../docs/man/anchore-${S}.1 "anchore $S"
done
