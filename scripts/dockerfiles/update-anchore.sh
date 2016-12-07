#!/bin/bash

if [ -d "/root/anchore_modules/" ]; then
    for p in `ls -1 /root/anchore_modules/anchore-modules*.rpm 2>/dev/null`
    do
	echo "installing extra anchore modules $p"
	yum -y install $p
	done
fi


while(true)
do
    anchore feeds sync
    anchore feeds sub vulnerabilities
    anchore feeds sync
    sleep 3600
done
