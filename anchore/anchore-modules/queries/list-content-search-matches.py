#!/usr/bin/env python

import sys
import os
import re
import json
import traceback

import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <filename> <filename> ...\nhelp: use 'all' to show all content search match filenames")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    print "Query requires input: all ..."

imageId = config['imgid']

outlist = list()
warns = list()

outlist.append(["Image_Id", "Repo_Tags", "File", "Match_Regexp", "Match_Line_Numbers"])

try:
    # handle the good case, something is found resulting in data matching the required columns
    results = anchore.anchore_utils.load_analysis_output(imageId, 'content_search', 'regexp_matches.all')
    for thefile in results.keys():
        data = json.loads(results[thefile])
        for b64regexp in data:
            theregexp = b64regexp.decode('base64')
            thelinenos = ','.join([str(x) for x in data[b64regexp]])
            outlist.append([config['meta']['shortId'], config['meta']['humanname'], thefile, theregexp, thelinenos])

except Exception as err:
    # handle the case where something wrong happened
    import traceback
    traceback.print_exc()
    warns.append("Query failed for image ("+str(config['imgid'])+") with exception: " + str(err))

# handle the no match case
if len(outlist) < 1:
    #outlist.append(["NOMATCH", "NOMATCH", "NOMATCH"])
    pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

if len(warns) > 0:
    anchore.anchore_utils.write_plainfile_fromlist(config['output_warns'], warns)

sys.exit(0)
