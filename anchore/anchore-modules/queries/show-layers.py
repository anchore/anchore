#!/usr/bin/env python

import sys
import os
import re
import json
import traceback

import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: all\nhelp: shows image layer IDs")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    print "Query requires input: all"


warns = list()
outlist = list()

outlist.append(["Image_Id", "Repo_Tags", "Layer"])

try:
    idata = anchore.anchore_utils.load_image_report(config['imgid'])
    layers = idata['layers']
    for layer in layers:
        outlist.append([config['meta']['shortId'], config['meta']['humanname'], str(layer)])
    outlist.append([config['meta']['shortId'], config['meta']['humanname'], str(config['imgid'])])
except Exception as err:
    # handle the case where something wrong happened
    import traceback
    traceback.print_exc()
    warns.append("query error: "+str(err))
    pass

# handle the no match case
if len(outlist) < 1:
    #outlist.append(["NOMATCH", "NOMATCH", "NOMATCH"])
    pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

if len(warns) > 0:
    anchore.anchore_utils.write_plainfile_fromlist(config['output_warns'], warns)

sys.exit(0)



