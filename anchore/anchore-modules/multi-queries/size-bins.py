#!/usr/bin/env python

import sys
import os
import re
import collections
import anchore.anchore_utils

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <default>| binmax0 binmax1 binmax2 ... binmaxN\nhelp: use 'default' for default bins, otherwith specify a list of integers starting with 0 to define custom bins.  ex: 0 10 100 200")
except:
    sys.exit(1)

if not config:
    sys.exit(0)

outlist = list()
warns = list()

custombins = list()
for name in config['params']:
    if name == 'all' or name == 'default':
        break
    try:
        custombins.append(int(name))
    except:
        warns.append(["Invalid query arguments specified, using defaults.  Input must be 'default' or a list of increasing integers (bin maximums: ex '10 20 50 100 1000')."])

if not custombins:
    bins = [0, 25, 50, 100, 250, 500, 1000]
else:
    bins = custombins

result = collections.OrderedDict()
for i in range(1, len(bins)):
    bstr = str(bins[i-1]) + "-" + str(bins[i])
    result[bstr] = {'count':0, 'imageIds':list()}
bstr = str(bins[-1]) + "++"
result[bstr] = {'count':0, 'imageIds':list()}

outlist.append(["Size_Range(MBs)", "Image_Count", "Image_Ids"])

allimages = {}
for imageId in config['images']:
    try:
        image_data = anchore.anchore_utils.load_image(imageId)
        megas = int(image_data['meta']['sizebytes']) / 1000000
        match = False
        for i in range(1, len(bins)):
            if megas <= bins[i]:
                bstr = str(bins[i-1]) + "-" + str(bins[i])
                result[bstr]['count'] += 1
                result[bstr]['imageIds'].append(imageId)
                match = True
                break
                
        if not match:
            bstr = str(bins[-1]) + "++"
            result[bstr]['count'] += 1
            result[bstr]['imageIds'].append(imageId)

    except Exception as err:
        warns.append(["cannot calculate size for image: " + imageId+ ": error: " + str(err)])

for bstr in result.keys():
    if result[bstr]['imageIds']:
        #outlist.append([bstr, str(result[bstr]['count']), ','.join(result[bstr]['imageIds'])])
        outlist.append([bstr, str(result[bstr]['count']), ' '.join(result[bstr]['imageIds'])])
    else:
        outlist.append([bstr, str(result[bstr]['count']), "N/A"])

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)
if len(warns) > 0:
    anchore.anchore_utils.write_kvfile_fromlist(config['output_warns'], warns)

allimages.clear()
sys.exit(0)
