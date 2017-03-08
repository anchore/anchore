#!/usr/bin/env python

import sys
import os
import re
import json
import traceback

import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: all\nhelp: shows dockerfile lines.")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    print "Query requires input: all"


warns = list()
outlist = list()

outlist.append(["Image_Id", "Repo_Tags", "Image Type"])

try:
    idata = anchore.anchore_utils.load_image_report(config['imgid'])
    ftree = idata['familytree']
    for fid in ftree:
        tags = "unknown"
        itype = "unknown"
        try:
            fdata = anchore.anchore_utils.load_image_report(fid)

            tags = ','.join(fdata['anchore_all_tags'])
            if not tags:
                tags = "none"

            itype = fdata['meta']['usertype']
            if not itype:
                itype = "intermediate"
        except:
            warns.append("family tree id ("+str(fid)+") does not appear to have been analyzed, no data for this member of the tree")

        outlist.append([fid, str(tags), str(itype)])

except Exception as err:
    # handle the case where something wrong happened
    import traceback
    traceback.print_exc()
    warns.append("query error: "+str(err))
    pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

if len(warns) > 0:
    anchore.anchore_utils.write_plainfile_fromlist(config['output_warns'], warns)

sys.exit(0)



