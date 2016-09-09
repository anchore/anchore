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
    if os.path.exists(os.path.join(unpackdir, "manifest.json")) and os.path.exists(os.path.join(unpackdir, "Dockerfile")):
        with open(os.path.join(unpackdir, "manifest.json"), 'r') as FH:
            manifest = json.loads(FH.read())

        ddata = anchore.anchore_utils.read_plainfile_tolist(os.path.join(unpackdir, "Dockerfile"))
        layers = manifest[0]['Layers']

        if re.match("^ *FROM scratch.*", ddata[0]):
            del ddata[0]

        lsizes = list()
        for l in layers:
            lfile = os.path.join(unpackdir, l)
            lsizes.append(str(os.path.getsize(lfile)))

        if len(ddata) == len(layers):
            for i in range(0, len(ddata)):
                clean_layer = re.sub("/layer.tar", "", layers[i])
                line = {'layer':clean_layer, 'dockerfile_line':ddata[i], 'layer_sizebytes':lsizes[i]}
                output.append(line)
except:
    pass

ofile = os.path.join(outputdir, 'layers_to_dockerfile')
anchore.anchore_utils.write_kvfile_fromdict(ofile, {'dockerfile_to_layer_map':json.dumps(output)})

sys.exit(0)
