#!/usr/bin/env python
import sys
import os
import re
import traceback

import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <distro> <distro> ...\nhelp: Shows the distro/version that the container image is based on - use 'all' for all or specify a string to filter the results.")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    print "Query requires input: all | <distro> <distro> ..."

outlist = list()
outlist.append(["Image_Id", "Repo_Tag", "Distro", "Version"])

try:
    # handle the good case, something is found resulting in data matching the required columns

    distrodict = anchore.anchore_utils.get_distro_from_imageId(config['imgid'])

    tags = "none"
    if config['meta']['humanname']:
        tags = config['meta']['humanname']

    distro = "unknown"
    if 'DISTRO' in distrodict:
        distro = distrodict['DISTRO']
        
    distrovers = "unknown"
    if 'DISTROVERS' in distrodict:
        distrovers = distrodict['DISTROVERS']

    match=False
    for d in config['params']:
        if d == 'all' or d == 'ALL':
            match = True
            break
        if d == distro or d == distro+':'+distrovers:
            match = True
            break

    if match:
        outlist.append([config['meta']['shortId'], tags, distro, distrovers])

except Exception as err:
    print str(err)
    traceback.print_exc()
    pass

# handle the no match case
if len(outlist) < 1:
    pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

sys.exit(0)



