#!/usr/bin/env python

import sys
import os
import shutil
import re
import json
import time
import subprocess
import anchore.anchore_utils

analyzer_name = "analyzer_meta"

try:
    config = anchore.anchore_utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print str(err)
    sys.exit(1)

imgname = config['imgid']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

# figure out the distro/version
outfile = outputdir + "/analyzer_meta"
meta = anchore.anchore_utils.get_distro_from_path('/'.join([unpackdir, "rootfs"]))

FH=open(outfile, 'w')
for k in meta.keys():
    FH.writelines(k + " " + meta[k] + "\n")
FH.close()
shutil.copy(outfile, unpackdir + "/analyzer_meta")

sys.exit(0)


