#!/usr/bin/env python

import sys
import os
import json
import re
import anchore 

from anchore import anchore_utils

gate_name = "GATENAMEHERE"
triggers = {
    'TRIGGER1':
    {
        'description':'triggers if this happens',
        'params':'TRIGGER1_PARAMS'
    },
    'TRIGGER2':
    {
        'description':'triggers if that happens',
        'params':'None'
    },
}
try:
    config = anchore.anchore_utils.init_gate_cmdline(sys.argv, gate_name, gate_help=triggers)
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    print "ERROR: could not set up environment for gate"
    sys.exit(1)

imgid = config['imgid']

try:
    params = config['params']
except:
    params = None

outlist = list()
# do somthing
try:
    image = anchore.anchore_image.AnchoreImage(imgid, allimages={})
    #outlist.append("TRIGGER1 Some text")
except Exception as err:
    #print "ERROR: could not do something" + str(err)
    exit(1)

# write output
anchore.anchore_utils.save_gate_output(imgid, gate_name, outlist)

sys.exit(0)
