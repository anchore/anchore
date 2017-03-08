#!/usr/bin/env python

import sys
import os
import re
import traceback

import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <thing> <thing> ...\nhelp: helpstring sentence")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    print "Query requires input: <packageA> <packageB> ..."


outlist = list()
warns = list()

outlist.append(["COL0", "COL1", "COL2"])

try:
    # handle the good case, something is found resulting in data matching the required columns
    
    #oulist.append(["VAL0", "VAL1", "VAL2"])
    pass
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



