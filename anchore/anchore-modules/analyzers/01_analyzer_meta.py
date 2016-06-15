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
meta = {}
outfile = outputdir + "/analyzer_meta"
osfile = unpackdir + "/rootfs/etc/os-release"
if os.path.exists(osfile):
    FH=open(osfile, 'r')
    for l in FH.readlines():
        l = l.strip()
        try:
            (key, val) = l.split("=")
            val = re.sub(r'"', '', val)
            if key == "ID":
                meta['DISTRO'] = val
            elif key == "VERSION_ID":
                meta['DISTROVERS'] = val
            elif key == "ID_LIKE":
                meta['LIKEDISTRO'] = ','.join(val.split())
        except:
            a=1

    FH.close()
elif os.path.exists(unpackdir + "/rootfs/etc/system-release-cpe"):
    FH=open(unpackdir +"/rootfs/etc/system-release-cpe", 'r')
    for l in FH.readlines():
        l = l.strip()
        try:
            distro = l.split(':')[2]
            vers = l.split(':')[4]
            meta['DISTRO'] = distro
            meta['DISTROVERS'] = vers
        except:
            pass
    FH.close()
elif os.path.exists(unpackdir + "/rootfs/bin/busybox"):
    meta['DISTRO'] = "busybox"
    try:
        sout = subprocess.check_output([unpackdir+"/rootfs//bin/busybox"])
        fline = sout.splitlines(True)[0]
        slist = fline.split()
        meta['DISTROVERS'] = slist[1]
    except:
        meta['DISTROVERS'] = "0"

if 'DISTRO' not in meta:
    meta['DISTRO'] = "Unknown"
    meta['DISTROVERS'] = "0"


FH=open(outfile, 'w')
for k in meta.keys():
    FH.writelines(k + " " + meta[k] + "\n")
FH.close()
shutil.copy(outfile, unpackdir + "/analyzer_meta")

sys.exit(0)


