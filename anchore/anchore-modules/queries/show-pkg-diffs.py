#!/usr/bin/env python

import sys
import os
import re

import anchore.anchore_image
import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <image ID to compare to> <another image ID> ...\nhelp: use 'base' to compare against base image")
except:
    sys.exit(1)

if not config:
    sys.exit(0)

outlist = list()
outlist.append(["ImageId", "Repo/Tag", "CompareImageId","Package","InputImageVersion","CompareImageVersion"])

allimages = {}
image = anchore.anchore_image.AnchoreImage(config['imgid'], config['anchore_config']['image_data_store'], allimages)
ipkgs = image.get_allpkgs()
hascontent = False

for fid in config['params']:
    try:
        fimageId = fid

        if fid == 'base':
            fimageId = image.get_earliest_base()

        fimage = anchore.anchore_image.AnchoreImage(fimageId, config['anchore_config']['image_data_store'], allimages)

        fpkgs = fimage.get_allpkgs()

        image_report = image.get_compare_report()

        if fimageId in image_report.keys():

            for p in image_report[fimageId]['package_list']['pkgs.all']:

                (pkg, status) = re.match('(\S*)\s*(.*)', p).group(1, 2)
                ivers = ipkgs.pop(pkg, "NA")

                if status == 'VERSION_DIFF':
                    pvers = fpkgs.pop(pkg, "NA")
                    outlist.append([config['meta']['shortId'], config['meta']['humanname'], fid,pkg,ivers,pvers])
                    hascontent=True
                elif status == 'INIMG_NOTINBASE':
                    outlist.append([config['meta']['shortId'], config['meta']['humanname'], fid,pkg,ivers,"NOTINSTALLED"])
                    hascontent=True
    except:
        pass

if not hascontent:
    #outlist.append(["NOMATCH","NOMATCH","NOMATCH","NOMATCH"])
    pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

allimages.clear()    
sys.exit(0)
