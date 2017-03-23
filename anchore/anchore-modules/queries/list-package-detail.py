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
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <package name> <package name> ...\nhelp: use 'all' to show all packages")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    print "Query requires input: <package name> <package name> ..."

outlist = list()
outlist.append(["Image_Id", "Repo_Tags", "Package_Name", "Version", "Arch", "Type", "Size", "Origin", "License"])

try:
    # handle the good case, something is found resulting in data matching the required columns
    allimages = {}

    pkgdetail_data = anchore.anchore_utils.load_analysis_output(config['imgid'], 'package_list', 'pkgs.allinfo')
    for pname in pkgdetail_data.keys():
        jsonstr = pkgdetail_data[pname]
        match = False
        if 'all' in config['params']:
            match = True
        else:
            for prefix in config['params']:
                if re.match(prefix, pname):
                    match = True
                    break
        
        if not match:
            continue

        pkgdata = json.loads(jsonstr)
        name = pname
        
        
        version = "N/A"
        if pkgdata['version']:
            if pkgdata['release'] and pkgdata['release'] != "N/A":
                version = pkgdata['version'] + "-" + pkgdata['release']
            else:
                version = pkgdata['version']

        arch = "N/A"
        if pkgdata['arch']:
            arch = pkgdata['arch']

        ptype = "N/A"
        if pkgdata['type']:
            ptype = pkgdata['type']
        
        size = "N/A"
        if str(pkgdata['size']):
            size = str(pkgdata['size'])
            
        origin = "N/A"
        if pkgdata['origin']:
            origin = pkgdata['origin']

        license = "N/A"
        if pkgdata['license']:
            license = pkgdata['license']
        

        #outlist.append([config['meta']['shortId'], config['meta']['humanname'], pname, pkgdata['version'] + "-" + pkgdata['release'], pkgdata['arch'], pkgdata['type'], str(pkgdata['size']), pkgdata['origin'], pkgdata['license']])
        outlist.append([config['meta']['shortId'], config['meta']['humanname'], pname, version, arch, ptype, size, origin, license])

except Exception as err:
    # handle the case where something wrong happened
    print "ERROR: " + str(err)

# handle the no match case
if len(outlist) < 1:
    # outlist.append(["NOMATCH", "NOMATCH", "NOMATCH"])
    pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

sys.exit(0)



