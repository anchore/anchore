#!/usr/bin/env python

import sys
import os
import shutil
import re
import json
import time
import rpm
import subprocess
import stat
import tarfile
import time
import hashlib

import anchore.anchore_utils

analyzer_name = "file_checksums"

try:
    config = anchore.anchore_utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print str(err)
    sys.exit(1)

imgname = config['imgid']
imgid = config['imgid_full']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

#if not os.path.exists(outputdir):
#    os.makedirs(outputdir)

domd5 = True
outfiles_md5 = {}
outfiles_sha256 = {}

try:
    timer = time.time()
    (tmp, allfiles) = anchore.anchore_utils.get_files_from_path(unpackdir + "/rootfs")
    for name in allfiles.keys():
        name = re.sub("^\.", "", name)
        thefile = '/'.join([unpackdir, "rootfs", name])

        csum = "DIRECTORY_OR_OTHER"
        if os.path.isfile(thefile) and not os.path.islink(thefile):
            if domd5:
                csum = "DIRECTORY_OR_OTHER"
                try:
                    with open(thefile, 'r') as FH:
                        csum = hashlib.md5(FH.read()).hexdigest()
                except:
                    pass
                outfiles_md5[name] = csum

            try:
                with open(thefile, 'r') as FH:
                    csum = hashlib.sha256(FH.read()).hexdigest()
            except:
                pass

            outfiles_sha256[name] = csum

        else:
            outfiles_md5[name] = "DIRECTORY_OR_OTHER"
            outfiles_sha256[name] = "DIRECTORY_OR_OTHER"

except Exception as err:
    import traceback
    traceback.print_exc()
    print "ERROR: " + str(err)
    raise err

if outfiles_md5:
    ofile = os.path.join(outputdir, 'files.md5sums')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outfiles_md5)

if outfiles_sha256:
    ofile = os.path.join(outputdir, 'files.sha256sums')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outfiles_sha256)


sys.exit(0)
