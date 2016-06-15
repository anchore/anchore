#!/usr/bin/env python

import sys
import os
import re

import anchore.anchore_image
import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <image ID to compare to> <another image ID> ...\nhelp: use 'base' for comparison against base image")
except:
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    config['params'] = ['base']

outlist = list()
outlist.append(["ImageID", "Repo/Tag", "CompareID", "File", "InputImageFileChecksum","CompareImageChecksum"])

allimages = {}
image = anchore.anchore_image.AnchoreImage(config['imgid'], config['anchore_config']['image_data_store'], allimages)
ipkgs = image.get_allfiles()

hascontent = False

for fid in config['params']:
    try:
        fimageId = fid

        if fid == 'base':
            fimageId = image.get_earliest_base()

        fimage = anchore.anchore_image.AnchoreImage(fimageId, config['anchore_config']['image_data_store'], allimages)
        fpkgs = fimage.get_allfiles()

        image_report = image.get_compare_report()
        if fimageId in image_report.keys():
            for p in image_report[fimageId]['file_checksums']['files.md5sums']:
                (pkg, status) = re.match('(\S*)\s*(.*)', p).group(1, 2)
                ivers = ipkgs.pop(pkg, "NA")
                if status == 'VERSION_DIFF':
                    pvers = fpkgs.pop(pkg, "NA")
                    outlist.append([config['meta']['shortId'], config['meta']['humanname'], fid, pkg, ivers, pvers])
                    hascontent=True
                elif status == 'INIMG_NOTINBASE':
                    outlist.append([config['meta']['shortId'], config['meta']['humanname'], fid, pkg, ivers, "NOTINSTALLED"])
                    hascontent=True
    except Exception as err:
        print err
        pass

if not hascontent:
    pass


anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

allimages.clear()    
sys.exit(0)
