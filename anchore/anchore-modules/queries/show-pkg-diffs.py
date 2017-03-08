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

if len(config['params']) <= 0:
    config['params'] = ['base']

outlist = list()
warns = list()
outlist.append(["Image_Id", "Repo_Tag", "Compare_Image_Id","Package","Input_Image_Version","Compare_Image_Version"])

allimages = {}
imageId = config['imgid']

try:
    image = anchore.anchore_image.AnchoreImage(imageId, allimages=allimages)
    ipkgs = image.get_allpkgs()

    for fid in config['params']:
        try:
            fimageId = False
            if fid == 'base':
                fimageId = image.get_earliest_base()
            else:
                try:
                    fimageId = anchore.anchore_utils.discover_imageId(fid)
                except ValueError as err:
                    warns.append("Cannot lookup imageId specified as input parameter: " + fid)

            if fimageId:
                if not anchore.anchore_utils.is_image_analyzed(fimageId):
                    raise Exception("imageId ("+str(fimageId)+") is not analyzed or analysis failed")

                fimage = anchore.anchore_image.AnchoreImage(fimageId, allimages=allimages)
                image_report = anchore.anchore_utils.diff_images(image.meta['imageId'], fimage.meta['imageId'])
                fpkgs = fimage.get_allpkgs()

                # do some checks
                if not image_report or 'package_list' not in image_report:
                    raise Exception("could not load package_list data after diff_images")

                for module_type in ['base', 'extra', 'user']:
                    if module_type in image_report['package_list']['pkgs.all']:
                        for pkg in image_report['package_list']['pkgs.all'][module_type].keys():
                            status = image_report['package_list']['pkgs.all'][module_type][pkg]
                            ivers = ipkgs.pop(pkg, "N/A")
                            pvers = fpkgs.pop(pkg, "N/A")

                            if status == 'VERSION_DIFF':
                                outlist.append([config['meta']['shortId'], config['meta']['humanname'], fimage.meta['shortId'], pkg, ivers,pvers])
                            elif status == 'INIMG_NOTINBASE':
                                outlist.append([config['meta']['shortId'], config['meta']['humanname'], fimage.meta['shortId'], pkg, ivers,"NOTINSTALLED"])
                            elif status == 'INBASE_NOTINIMG':
                                outlist.append([config['meta']['shortId'], config['meta']['humanname'], fimage.meta['shortId'], pkg, "NOTINSTALLED", pvers])

        except Exception as err:
            import traceback
            traceback.print_exc()
            warns.append("problem comparing image ("+str(imageId)+") with image ("+str(fid)+"): exception: " + str(err))
except Exception as err:
    warns.append("failed to run query: exception: " + str(err))

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)
if len(warns) > 0:
    anchore.anchore_utils.write_plainfile_fromlist(config['output_warns'], warns)

allimages.clear()    
sys.exit(0)
