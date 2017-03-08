#!/usr/bin/env python

import sys
import os
import stat
import re
import json
import traceback

import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <license string> <license string> ...\nhelp: use 'all' to show all package/licenses")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    print "Query requires input: <package name> <package name> ..."

outlist = list()
outlist.append(["Image_Id", "Repo_Tags", "Package", "Version", "License(s)"])

try:
    # handle the good case, something is found resulting in data matching the required columns
    adata = anchore.anchore_utils.load_analysis_output(config['imgid'], 'package_list', 'pkgs.allinfo')
    for pname in adata.keys():
        #(pname, jsonstr) = re.match('(\S*)\s*(.*)', datum).group(1, 2)
        jsonstr = adata[pname]

        pkgdata = json.loads(jsonstr)
        for k in pkgdata.keys():
            if isinstance(pkgdata[k], basestring):
                pkgdata[k] = '_'.join(pkgdata[k].split())

        match = False
        if 'all' in config['params']:
            match = True
        else:
            for licfilter in config['params']:
                if re.match('.*\*', licfilter):
                    licfilter = re.sub("\*", "", licfilter)
                    if re.match(".*"+licfilter+".*", pkgdata['license']):
                        match = True
                        break
                    
                elif licfilter in pkgdata['license'].split("_"):
                    match = True
                    break
                
        if match:

            if 'release' in pkgdata and (pkgdata['release'] != 'N/A'):
                vstring = pkgdata['version'] + "-" + pkgdata['release']
            else:
                vstring = pkgdata['version']

            outlist.append([config['meta']['shortId'], config['meta']['humanname'], pname, vstring, pkgdata['license']])


except Exception as err:
    # handle the case where something wrong happened
    print "ERROR: " + str(err)

# handle the no match case
if len(outlist) < 1:
    # outlist.append(["NOMATCH", "NOMATCH", "NOMATCH"])
    pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

sys.exit(0)



