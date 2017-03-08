#!/usr/bin/env python

import sys
import os
import re
import anchore.anchore_utils

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <all> ...\nhelp: use 'all'")
except:
    sys.exit(1)

if not config:
    sys.exit(0)

for name in config['params']:
    if True:
        break

outlist = list()
warns = list()
outlist.append(["COL0", "COL1"])

result = {}

allimages = {}
for imageId in config['images']:
    try:
        image = anchore.anchore_image.AnchoreImage(imageId, allimages=allimages)
        outlist.append(["ROW0-0", "ROW0-1"])
    except Exception as err:
        warns.append(["somethin"])

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)
if len(warns) > 0:
    anchore.anchore_utils.write_kvfile_fromlist(config['output_warns'], warns)

allimages.clear()
sys.exit(0)
