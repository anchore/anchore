#!/bin/bash

if [ ! -f 'setup.py' -o ! -d 'anchore' ]; then
    echo "Looks like you are not running this from the root anchore code checkout - go there and try again (cd /path/to/checkout/of/anchore; ./scripts/release/make-rpm.sh)"
    exit 1
fi

REL=$1

if [ -z "$REL" ]; then
    echo "Need to pass a release number/string as parameter to this script"
    exit 1
fi


python setup.py --command-packages=stdeb.command sdist_dsc --debian-version "$REL" --depends "python-click,python-clint,python-docker,python-prettytable,python-yaml,python-colorama,python-args,python-websocket,libyaml-0-2,python-backports.ssl-match-hostname,python-rpm,yum" bdist_deb
python setup.py clean --all
