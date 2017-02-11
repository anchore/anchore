#!/usr/bin/env python

import sys
import os
import json
import re
import anchore 

from anchore import anchore_utils

gate_name = "IMAGECHECK"
triggers = {
    'BASEOUTOFDATE':
    {
        'description':'triggers if the image\'s base image has been updated since the image was built/analyzed',
        'params':'None'
    }
}
try:
    config = anchore.anchore_utils.init_gate_cmdline(sys.argv, gate_name, gate_help=triggers)
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    print "ERROR: could not set up environment for gate"
    sys.exit(1)

imageId = config['imgid']

try:
    params = config['params']
except:
    params = None

outlist = list()
# do somthing
try:
    idata = anchore.anchore_utils.load_image_report(imageId)
    humanname = idata['meta']['humanname']

    dockerfile_mode = idata['dockerfile_mode']
    if dockerfile_mode == 'Actual':
        realbaseid = None
        if idata and 'familytree' in idata and len(idata['familytree']) > 0:
            realbaseid = idata['familytree'][0]

        (thefrom, thefromid) = anchore.anchore_utils.discover_from_info(idata['dockerfile_contents'])
        if realbaseid != thefromid:
            outlist.append("BASEOUTOFDATE Image base image ("+str(thefrom)+") ID is ("+str(realbaseid)[0:12]+"), but the latest ID for ("+str(thefrom)+") is ("+str(thefromid)[0:12]+")")

except Exception as err:
    outlist.append(gate_name + " gate failed to run with exception: " + str(err))
    exit(1)

# write output
anchore.anchore_utils.save_gate_output(imageId, gate_name, outlist)

sys.exit(0)
