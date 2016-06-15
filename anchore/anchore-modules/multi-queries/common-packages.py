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
        nimage = anchore.anchore_image.AnchoreImage(i, config['anchore_config']['image_data_store'], allimages)
        return([imageId] + get_next(nimage, allimages))
        
    return([imageId, image.get_earliest_base()])


try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <base image ID> <base image ID> ...\nhelp: use 'all' to show all base image IDs")
except:
    sys.exit(1)

if not config:
    sys.exit(0)

OFH=open(config['output'], 'w')
OFH.write("BaseId Package *ChildImagesWithPackage\n")

allimages = {}
tups = list()
for imageId in config['images']:
    image = anchore.anchore_image.AnchoreImage(imageId, config['anchore_config']['image_data_store'], allimages)
    branch = get_next(image, allimages)
    for i in range(0, len(branch)-1):
        tup = [branch[i], branch[i+1]]
        if not tup in tups:
            tups.append(tup)

pkgout = {}

for t in tups:
    s = t[0]
    d = t[1]
    thedir = '/'.join([config['dirs']['datadir'], s, 'compare_output', d])
    image = allimages[s]
    base = image.get_earliest_base()
    bimage = allimages[d]
    
    if base not in pkgout:
        pkgout[base] = {}

    try:
        report = image.get_compare_report().copy().pop(d, {})
        for l in report['package_list']['pkgs.all']:
            l = l.strip()
            (k, v) = re.match('(\S*)\s*(.*)', l).group(1, 2)
            if not k in pkgout[base]:
                pkgout[base][k] = 0
            pkgout[base][k] = pkgout[base][k] + 1
    except Exception as e:
        pass

for k in pkgout.keys():
    for p in pkgout[k].keys():
        if 'all' in config['params'] or k in config['params'] or k[0:12] in config['params']:
            OFH.write(k[0:12] + " " + p + " " + str(pkgout[k][p]) + "\n")

OFH.close()
allimages.clear()
sys.exit(0)
