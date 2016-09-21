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
warns = list()

outlist.append(["Image_Id", "Repo_Tag", "Compare_Image_Id", "File", "Input_Image_File_Checksum","Compare_Image_Checksum"])

allimages = {}
image = anchore.anchore_image.AnchoreImage(config['imgid'], config['anchore_config']['image_data_store'], allimages)
ipkgs = image.get_allfiles()
hascontent = False

for fid in config['params']:
    try:
        fimageId = False
        if fid == 'base':
            fimageId = image.get_earliest_base()
        else:
            try:
                fimageId = anchore.anchore_utils.discover_imageId(fid).keys()[0]
            except ValueError as err:
                warns.append("Cannot lookup imageId specified as input parameter: " + fid)

        if fimageId:
            fimage = anchore.anchore_image.AnchoreImage(fimageId, config['anchore_config']['image_data_store'], allimages)

            image_report = anchore.anchore_utils.diff_images(image.meta['imageId'], fimage.meta['imageId'])
            fpkgs = fimage.get_allfiles()

            csumkey = 'files.md5sums'
            if 'files.sha256sums' in image_report['file_checksums']:
                csumkey = 'files.sha256sums'
            for module_type in ['base', 'extra', 'user']:
                if module_type in image_report['package_list']['pkgs.all']:
                    for pkg in image_report['file_checksums'][csumkey][module_type].keys():
                        status = image_report['file_checksums'][csumkey][module_type][pkg]
                        ivers = ipkgs.pop(pkg, "NA")
                        pvers = fpkgs.pop(pkg, "NA")

                        if status == 'VERSION_DIFF':
                            outlist.append([config['meta']['shortId'], config['meta']['humanname'], fimage.meta['shortId'], pkg, ivers, pvers])
                            hascontent=True
                        elif status == 'INIMG_NOTINBASE':
                            outlist.append([config['meta']['shortId'], config['meta']['humanname'], fimage.meta['shortId'], pkg, ivers, "NOTINSTALLED"])
                            hascontent=True
                        elif status == 'INBASE_NOTINIMG':
                            outlist.append([config['meta']['shortId'], config['meta']['humanname'], fimage.meta['shortId'], pkg, "NOTINSTALLED", pvers])
                            hascontent=True

    except Exception as err:
        import traceback
        traceback.print_exc()
        print "WARN: " + str(err)

if not hascontent:
    pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

if len(warns) > 0:
    anchore.anchore_utils.write_plainfile_fromlist(config['output_warns'], warns)

allimages.clear()    
sys.exit(0)
