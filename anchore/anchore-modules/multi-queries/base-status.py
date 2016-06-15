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

outlist = list()
outlist.append(["InputImageId", "InputRepo/Tag", "CurrentBaseId", "CurrentBaseRepo/Tag", "Status", "LatestBaseId", "LatestBaseRepo/Tag"])

allimages = {}
for imageId in config['images']:
    try:

        image = anchore.anchore_image.AnchoreImage(imageId, config['anchore_config']['image_data_store'], allimages)

        bimageId = image.get_earliest_anchore_base()
        if bimageId:
            bimage = anchore.anchore_image.AnchoreImage(bimageId, config['anchore_config']['image_data_store'], allimages)
        else:
            bimage = image

        currtags = bimage.get_alltags_current()
        alltags = bimage.get_alltags_ever()
        checktags = list(set(alltags) - set(currtags))
        uptodate = True
        for t in checktags:
            try:
                cimage = anchore.anchore_image.AnchoreImage(t, config['anchore_config']['image_data_store'], allimages)
                cimageId = cimage.meta['imageId']
                if cimage.meta['imageId'] != bimage.meta['imageId']:
                    uptodate = False
            except:
                pass

        if uptodate:
            if 'all' in config['params'] or bimage.meta['shortId'] in config['params'] or bimage.meta['imageId'] in config['params']:
                outlist.append([image.meta['shortId'], image.meta['humanname'], bimage.meta['shortId'], bimage.get_human_name(), "up-to-date", "N/A", "N/A"])
        else:
            if 'all' in config['params'] or bimage.meta['shortId'] in config['params'] or bimage.meta['imageId'] in config['params']:
                outlist.append([image.meta['shortId'], image.meta['humanname'], bimage.meta['shortId'], bimage.get_human_name(), "out-of-date", cimage.meta['shortId'], cimage.get_human_name()])
    except:
        pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

allimages.clear()
sys.exit(0)
