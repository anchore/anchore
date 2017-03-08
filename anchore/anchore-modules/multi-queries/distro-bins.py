#!/usr/bin/env python

import sys
import os
import re
import anchore.anchore_utils

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <all|summary> ...\nhelp: use 'all' to show distros by version, use 'summarize' to show distro count with any version")
except:
    sys.exit(1)

if not config:
    sys.exit(0)

onlysummarize = False
for name in config['params']:
    if name == 'summarize':
        onlysummarize = True
        break

outlist = list()
warns = list()
outlist.append(["Distro", "Distro_Version", "*Image_Count", "Image_Ids"])

result = {}

allimages = {}
for imageId in config['images']:
    try:
        image = anchore.anchore_image.AnchoreImage(imageId, allimages=allimages)

        distro = image.get_distro()
        distro_vers = image.get_distro_vers()
        distro_str = distro + ":" + distro_vers

        if distro not in result:
            result[distro] = {}

        if distro_vers not in result[distro]:
            result[distro][distro_vers] = {'count':0, 'imageIds':list()}

        result[distro][distro_vers]['count'] = result[distro][distro_vers]['count'] + 1
        result[distro][distro_vers]['imageIds'].append(image.meta['imageId'])

    except Exception as err:
        warns.append(["Failed to read distro/version from image: " + image.meta['imageId']])

sums = {}
for d in result.keys():
    for v in result[d].keys():
        if not onlysummarize:
            #outlist.append([d, v, str(result[d][v]['count']), ','.join(result[d][v]['imageIds'])])
            outlist.append([d, v, str(result[d][v]['count']), ' '.join(result[d][v]['imageIds'])])

        if d not in sums:
            sums[d] = {'count':0, 'imageIds':list()}
        sums[d]['count'] = sums[d]['count'] + result[d][v]['count']
        sums[d]['imageIds'] = sums[d]['imageIds'] + result[d][v]['imageIds']

if onlysummarize:
    for k in sums.keys():
        #outlist.append([k, 'any', str(sums[k]['count']), ','.join(sums[k]['imageIds'])])
        outlist.append([k, 'any', str(sums[k]['count']), ' '.join(sums[k]['imageIds'])])

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)
if len(warns) > 0:
    anchore.anchore_utils.write_kvfile_fromlist(config['output_warns'], warns)

allimages.clear()
sys.exit(0)
