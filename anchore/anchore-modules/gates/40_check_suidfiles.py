#!/usr/bin/env python

import sys
import os
import re
import anchore.anchore_utils

try:
    config = anchore.anchore_utils.init_gate_cmdline(sys.argv, "CVE Checking Gate")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

imgid = config['imgid']
imgdir = config['dirs']['imgdir']
analyzerdir = config['dirs']['analyzerdir']
comparedir = config['dirs']['comparedir']
outputdir = config['dirs']['outputdir']

try:
    params = config['params']
except:
    params = None

if not os.path.exists(imgdir):
    sys.exit(0)

metafile = '/'.join([imgdir, 'image_info', 'image.meta'])
meta = {}
FH=open(metafile, 'r')
for l in FH.readlines():
    l=l.strip()
    (k, v) = re.match('(\S*)\s*(.*)', l).group(1, 2)
    meta[k] = v
FH.close()

if meta['usertype'] != "user":
    sys.exit(0)


output = '/'.join([outputdir, 'SUIDDIFF'])
OFH=open(output, 'w')

pkgfile = '/'.join([comparedir, 'base', 'file_suids', 'files.suids'])
if not os.path.exists(pkgfile):
    sys.exit(0)

isdiff = 0
FH=open(pkgfile, 'r')
for l in FH.readlines():
    isdiff = 1
    l = l.strip()
    (pkg, status) = re.match('(\S*)\s*(.*)', l).group(1, 2)

    if (status == 'VERSION_DIFF'):
        OFH.write("SUIDMODEDIFF SUID file mode in container is different from baseline for file - " + pkg + "\n")
    elif (status == 'INIMG_NOTINBASE'):
        OFH.write("SUIDFILEADD SUID file has been added to image since base - " + pkg + "\n")
    elif (status == 'INBASE_NOTINIMG'):
        OFH.write("SUIDFILEDEL SUID file has been removed from image since base - " + pkg + "\n")
FH.close()

if (isdiff):
    OFH.write("SUIDDIFF SUID file manifest is different from image to base\n")

OFH.close()

sys.exit(0)
