#!/usr/bin/env python

import sys
import os
import re
import anchore.anchore_utils

def get_next(image, allimages):
    if image.meta['imageId'] not in allimages:
        allimages[image.meta['imageId']] = image

    imageId = image.meta['imageId']
    i = image.get_latest_userimage()
    if i:
        nimage = anchore.anchore_image.AnchoreImage(i, allimages=allimages)
        return([imageId] + get_next(nimage, allimages))
        
    return([imageId, image.get_earliest_base()])


try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <base image ID> <base image ID> ...\nhelp: use 'all' to show all base image IDs")
except:
    sys.exit(1)

if not config:
    sys.exit(0)

outlist = list()
outlist.append(["BaseId", "Package", "*Child_Images_With_Package"])

allimages = {}
tups = list()
for imageId in config['images']:
    image = anchore.anchore_image.AnchoreImage(imageId, allimages=allimages)
    branch = get_next(image, allimages)
    for i in range(0, len(branch)-1):
        tup = [branch[i], branch[i+1]]
        if not tup in tups:
            tups.append(tup)

pkgout = {}

for t in tups:
    s = t[0]
    d = t[1]

    image = allimages[s]
    base = image.get_earliest_base()
    bimage = allimages[d]
    
    if base not in pkgout:
        pkgout[base] = {}

    try:
        diffdata = anchore.anchore_utils.diff_images(image.meta['imageId'], d)
        pkgdiffs = diffdata.pop('package_list', {}).pop('pkgs.all', {})
        for module_type in pkgdiffs.keys():
            for k in pkgdiffs[module_type].keys():
                if pkgdiffs[module_type][k] == 'INIMG_NOTINBASE':
                    if k not in pkgout[base]:
                        pkgout[base][k] = 0
                    pkgout[base][k] = pkgout[base][k] + 1
    except Exception as e:
        pass

for k in pkgout.keys():
    for p in pkgout[k].keys():
        if 'all' in config['params'] or k in config['params'] or k[0:12] in config['params']:
            outlist.append([k[0:12], p, str(pkgout[k][p])])

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

allimages.clear()
sys.exit(0)
