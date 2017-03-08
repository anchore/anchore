#!/usr/bin/env python

import sys
import os
import re

import anchore.anchore_image
import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <image ID to compare to> <another image ID> exclude=</some/path> exclude=</some/other/path> ...\nhelp: use 'base' as an imageId for comparison against base image, and exclude=</some/path> to exclude results that begin with the supplied path string")
except:
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    config['params'] = ['base']

fids = list()
excludes = list()
for p in config['params']:
    try:
        (key, value) = p.split('=')
        if key == 'exclude':
            excludes.append(value)
    except:
        fids.append(p)

outlist = list()
warns = list()
outlist.append(["Image_Id", "Repo_Tag", "Compare_Image_Id", "File", "Input_Image_File_Checksum","Compare_Image_Checksum"])

allimages = {}
imageId = config['imgid']

try:
    image = anchore.anchore_image.AnchoreImage(imageId, allimages=allimages)
    ipkgs = image.get_allfiles()

    for fid in fids:
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
                fpkgs = fimage.get_allfiles()

                # do some checks
                if not image_report or 'file_checksums' not in image_report:
                    raise Exception("could not load file_checksums data after diff_images")

                csumkey = 'files.md5sums'
                if 'files.sha256sums' in image_report['file_checksums']:
                    csumkey = 'files.sha256sums'

                for module_type in ['base', 'extra', 'user']:
                    if module_type in image_report['file_checksums'][csumkey]:
                        for pkg in image_report['file_checksums'][csumkey][module_type].keys():

                            skip = False
                            for e in excludes:
                                if re.match("^"+e, pkg):
                                    skip = True
                                    break

                            if skip:
                                continue

                            status = image_report['file_checksums'][csumkey][module_type][pkg]
                            ivers = ipkgs.pop(pkg, "N/A")
                            pvers = fpkgs.pop(pkg, "N/A")

                            if status == 'VERSION_DIFF':
                                outlist.append([config['meta']['shortId'], config['meta']['humanname'], fimage.meta['shortId'], pkg, ivers, pvers])
                            elif status == 'INIMG_NOTINBASE':
                                outlist.append([config['meta']['shortId'], config['meta']['humanname'], fimage.meta['shortId'], pkg, ivers, "NOTINSTALLED"])
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
