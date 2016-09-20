#!/usr/bin/env python

import sys
import os
import shutil
import re
import json
import time
import rpm
import subprocess

import anchore.anchore_utils

analyzer_name = "layer_info"

try:
    config = anchore.anchore_utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print str(err)
    sys.exit(1)

imgname = config['imgid']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

if not os.path.exists(outputdir):
    os.makedirs(outputdir)

output = list()

try:

    if os.path.exists(os.path.join(unpackdir, "docker_history.json")):
        with open(os.path.join(unpackdir, "docker_history.json"), 'r') as FH:
            history = json.loads(FH.read())

        for record in history:
            clean_layer = re.sub("^sha256:", "", record['Id'])
            if clean_layer == '<missing>':
                clean_layer = "unknown"
                
            clean_createdBy = re.sub(r"^/bin/sh -c #\(nop\) ", "", record['CreatedBy'])
            line = {'layer':clean_layer, 'dockerfile_line':clean_createdBy, 'layer_sizebytes':str(record['Size'])}
            output.append(line)
except:
    pass

ofile = os.path.join(outputdir, 'layers_to_dockerfile')
anchore.anchore_utils.write_kvfile_fromdict(ofile, {'dockerfile_to_layer_map':json.dumps(output)})

sys.exit(0)
