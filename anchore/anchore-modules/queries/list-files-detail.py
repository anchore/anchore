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
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <directory prefix> <directory prefix> ...\nhelp: use 'all' to show all files")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    print "Query requires input: <directory prefix> <directory prefix> ..."

outlist = list()
warns = list()
outlist.append(["Image_Id", "Repo_Tags", "Filename", "Type", "Size", "Mode", "Link_Dest", "Checksum"])

try:
    # handle the good case, something is found resulting in data matching the required columns

    detail_data = anchore.anchore_utils.load_analysis_output(config['imgid'], 'file_list', 'files.allinfo')
    checksum_data = anchore.anchore_utils.load_analysis_output(config['imgid'], 'file_checksums', 'files.sha256sums')
    if not checksum_data:
        checksum_data = anchore.anchore_utils.load_analysis_output(config['imgid'], 'file_checksums', 'files.md5sums')

    for fname in detail_data.keys():
        jsonstr = detail_data[fname]

        match = False
        if 'all' in config['params']:
            match = True
        else:
            for prefix in config['params']:
                if re.match("^"+prefix, fname):
                    match = True
                    break
        
        if not match:
            continue

        filedata = json.loads(jsonstr)
        if filedata['linkdst']:
            linkdst = filedata['linkdst']
        else:
            linkdst = "N/A"

        csum = "N/A"
        fname_dotprefix = "."+fname
        fname_slashpostfix = fname_dotprefix+"/"
        if fname in checksum_data:
            csum = checksum_data[fname]
        elif fname_dotprefix in checksum_data:
            csum = checksum_data[fname_dotprefix]
        elif fname_slashpostfix in checksum_data:
            csum = checksum_data[fname_slashpostfix]
        else:
            csum = "N/A"

        outlist.append([config['meta']['shortId'], config['meta']['humanname'], fname, filedata['type'], str(filedata['size']), oct(stat.S_IMODE(filedata['mode'])), linkdst, csum])

except Exception as err:
    # handle the case where something wrong happened
    import traceback
    traceback.print_exc()
    warns.append("query threw an exception: " + str(err))

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)
if len(warns) > 0:
    anchore.anchore_utils.write_plainfile_fromlist(config['output_warns'], warns)

sys.exit(0)



