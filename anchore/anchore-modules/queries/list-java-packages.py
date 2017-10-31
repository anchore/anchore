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
warns = list()

outlist.append(["Image_Id", "Repo_Tags", "*Package_Name", "Specification_Version", "Implementation_Version", "Location"])

try:
    # handle the good case, something is found resulting in data matching the required columns
    allimages = {}

    pkgdetail_data = anchore.anchore_utils.load_analysis_output(config['imgid'], 'package_list', 'pkgs.java')

    for pname in pkgdetail_data.keys():
        jsonstr = pkgdetail_data[pname]
        pkgdata = json.loads(pkgdetail_data[pname])

        name = pkgdata['name']
        
        match = False
        if 'all' in config['params']:
            match = True
        else:
            for prefix in config['params']:
                if re.match(prefix, name):
                    match = True
                    break
        
        if not match:
            continue

        sversion = pkgdata.pop('specification-version', 'Unknown')
        iversion = pkgdata.pop('implementation-version', 'Unknown')
        origin = pkgdata.pop('origin', 'N/A')
        lic = pkgdata.pop('license', 'Unknown')
        location = pkgdata.pop('location', 'Unknown')

        outlist.append([config['meta']['shortId'], config['meta']['humanname'], name, sversion, iversion, location])

except Exception as err:
    # handle the case where something wrong happened
    traceback.print_exc()
    warns.append("Query failed for image ("+str(config['imgid'])+") with exception: " + str(err))

print outlist
anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)
if len(warns) > 0:
    anchore.anchore_utils.write_plainfile_fromlist(config['output_warns'], warns)

sys.exit(0)



