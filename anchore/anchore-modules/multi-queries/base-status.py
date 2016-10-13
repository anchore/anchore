#!/usr/bin/env python

import sys
import os
import re
import anchore.anchore_utils

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <base image ID> <base image ID> ...\nhelp: use 'all' to show all base image IDs")
except:
    sys.exit(1)

if not config:
    sys.exit(0)

# clean up the input params into usable imageIds
newparams = list()

for name in config['params']:
    if name != 'all':
        try:
            imageId = anchore.anchore_utils.discover_imageId(name)
        except:
            imageId = name
    else:
        imageId = 'all'
    newparams.append(imageId)
config['params'] = newparams

print "PARAMS: " + str(config['params'])

outlist = list()
warns = list()
outlist.append(["Image_Id", "Repo_Tag", "From_Line", "Actual_Base_Id", "Current_From_Base_Id", "Status"])

result = {}

allimages = {}
for imageId in config['images']:
    try:
        idata = anchore.anchore_utils.load_image_report(imageId)
        humanname = idata['meta']['humanname']

        realbaseid = None
        if idata and 'familytree' in idata and len(idata['familytree']) > 0:
            realbaseid = idata['familytree'][0]
            
        (thefrom, thefromid) = anchore.anchore_utils.discover_from_info(idata['dockerfile_contents'])

        if realbaseid and thefromid:
            if realbaseid == imageId:
                outlist.append([imageId, humanname, thefrom, realbaseid, 'N/A', 'up-to-date'])
            elif thefromid == 'scratch' or thefromid == '<unknown>':
                outlist.append([imageId, humanname, thefrom, realbaseid, 'N/A', 'N/A'])
            elif realbaseid != thefromid:
                outlist.append([imageId, humanname, thefrom, realbaseid, thefromid, 'out-of-date'])
            else:
                outlist.append([imageId, humanname, thefrom, realbaseid, thefromid, 'up-to-date'])

        else:
            warns.append("imageId ("+imageId+"): could not evaluate base status: fromline="+str(thefrom)+" realbaseid="+str(realbaseid)+" fromid="+str(thefromid))

    except Exception as err:
        warns.append("Exception: " + str(err))

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)
if len(warns) > 0:
    anchore.anchore_utils.write_plainfile_fromlist(config['output_warns'], warns)

allimages.clear()
sys.exit(0)
