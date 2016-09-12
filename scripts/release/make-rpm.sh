#!/bin/bash

if [ ! -f 'setup.py' -o ! -d 'anchore' ]; then
    echo "Looks like you are not running this from the root anchore code checkout - go there and try again (cd /path/to/checkout/of/anchore; ./scripts/release/make-rpm.sh)"
    exit 1
fi

REL=$1

if [ -z "$REL" ]; then
    echo "Need to pass a release number as parameter to this script"
    exit 1
fi

python setup.py bdist_rpm --requires="python python-setuptools python2-clint PyYAML python-requests python-click python-prettytable python-docker-py dpkg rpm-python python-oauth2" --build-requires="python python-setuptools" --release="$REL"
python setup.py clean --all
