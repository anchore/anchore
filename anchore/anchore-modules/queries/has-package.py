#!/usr/bin/env python

import sys
import os
import re
import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <package> <package> ...\nhelp: search input image(s) for specified <package> installations")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    print "Query requires input: <packageA> <packageB> ..."

warns = list()
outlist = list()
outlist.append(["ImageID", "Repo/Tag", "QueryParam", "Package", "Version"])

try:
    pkgfile = '/'.join([config['dirs']['analyzerdir'], 'package_list', 'pkgs.all'])
    FH=open(pkgfile, 'r')

    pkgs = anchore.anchore_utils.read_kvfile_todict(pkgfile)
    
    if len(pkgs) <= 0 or (len(pkgs) == 1 and 'Unknown' in pkgs):
        warns.append(config['meta']['shortId'] + "(" + config['meta']['humanname'] + ") Image has been analyzed but package data is empty - nothing to search")

    for p in pkgs.keys():
        pkgs[p + "-" + pkgs[p]] = pkgs[p]

    for pkg in config['params']:
        
        if pkg in pkgs:
            version = pkgs[pkg]
            outlist.append([config['meta']['shortId'], config['meta']['humanname'], pkg, pkg, version])
        else:
            #outlist.append([pkg, "NOMATCH", "NOMATCH"])
            pass

except:
    #outlist.append(["NOMATCH", "NOMATCH", "NOMATCH"])
    pass

if len(outlist) < 2:
    #outlist.append(["NOMATCH", "NOMATCH", "NOMATCH"])
    pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

if len(warns) > 0:
    anchore.anchore_utils.write_plainfile_fromlist(config['output_warns'], warns)

sys.exit(0)
