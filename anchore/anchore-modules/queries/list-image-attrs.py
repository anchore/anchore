#!/usr/bin/env python

import sys
import os
import re
import time
import traceback

import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: all ...\nhelp: list summary information about image(s)")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    print "Query requires input: all ..."

outlist = list()
outlist.append(["Image_Id", "Repo_Tags", "Num_Layers", "Num_Disto_Packages", "Num_Files", "Num_Files_From_Distro_Pkgs", "Image_Size_Bytes", "Last_Analyzed"])

try:
    # handle the good case, something is found resulting in data matching the required columns
    imageId = config['meta']['imageId']
    
    image_data = anchore.anchore_utils.load_image(imageId)

    result = anchore.anchore_utils.load_analysis_output(imageId, 'package_list', 'pkgs.all')
    numpkgs = len(result.keys())

    result = anchore.anchore_utils.load_analysis_output(imageId, 'file_list', 'files.all')
    numfiles = len(result.keys())

    result = anchore.anchore_utils.load_analysis_output(imageId, 'file_list', 'files.nonpkged')
    numpkgfiles = numfiles - len(result.keys())

    aoutputs = list()
    amanifest = anchore.anchore_utils.load_analyzer_manifest(imageId)
    lasttime = 0
    for a in amanifest.keys():
        if amanifest[a]['timestamp'] > lasttime:
            lasttime = amanifest[a]['timestamp']
        
    #nicetime = time.ctime(int(lasttime)).split()
    #nicetime = ','.join(nicetime)
    nicetime = time.ctime(int(lasttime))
    #    aoutputs = list()
    #    alist = anchore.anchore_utils.list_analysis_outputs(imageId)
    #    for module_name in alist:
    #        for module_value in alist[module_name]:
    #            aoutputs.append(':'.join([module_name, module_value]))

    outlist.append([image_data['meta']['shortId'], image_data['meta']['humanname'], str(len(image_data['layers'])), str(numpkgs), str(numfiles), str(numpkgfiles), str(image_data['meta']['sizebytes']), nicetime])
except Exception as err:
    # handle the case where something wrong happened
    print str(err)
    pass

# handle the no match case
if len(outlist) < 1:
    pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)

sys.exit(0)



