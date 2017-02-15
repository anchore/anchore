#!/usr/bin/env python

import sys
import os
import re
import json
import anchore.anchore_utils

gate_name = "PKGCHECK"
triggers = {
    'PKGNOTPRESENT':
    {
        'description':'triggers if the evaluated image has a package installed with a different version of the same package from a previous base image',
        'params':'PKGFULLMATCH,PKGNAMEMATCH,PKGVERSMATCH'
    }
}


try:
    config = anchore.anchore_utils.init_gate_cmdline(sys.argv, gate_name, gate_help=triggers)
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

imgid = config['imgid']

params = []
try:
    for p in config['params']:
        toks = re.split(" +", p)
        params = toks
except:
    params = None

if not params:
    sys.exit(0)

fullmatch = {}
namematch = {}
vermatch = {}

for param in params:

    try:
        (p,v) = param.split("=")
        for pkgstring in v.split(","):
            try:
                try:
                    (pkg, vers) = pkgstring.split("|")
                except:
                    pkg = pkgstring
                    vers = None
                if p == 'PKGFULLMATCH':
                    fullmatch[pkg] = vers
                elif p == 'PKGNAMEMATCH':
                    namematch[pkg] = True
                elif p == 'PKGVERSMATCH':
                    vermatch[pkg] = vers
            except Exception as err:
                raise err
    except Exception as err:
        print "WARN: input param could not be parsed out, skipping: " + str(param)


print fullmatch
print namematch
print vermatch

outlist = list()
imageId = config['imgid']

anchore.anchore_utils.save_gate_output(imageId, gate_name, outlist)

sys.exit(0)
