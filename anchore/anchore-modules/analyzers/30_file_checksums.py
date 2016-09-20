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

if not os.path.exists(outputdir):
    os.makedirs(outputdir)

outfiles_md5 = {}
outfiles_sha256 = {}

try:

#    timer = time.time()
#    allfiles = {}
#    if os.path.exists(unpackdir + "/anchore_allfiles.json"):
#        with open(unpackdir + "/anchore_allfiles.json", 'r') as FH:
#            allfiles = json.loads(FH.read())
#    else:
#        fmap, allfiles = anchore.anchore_utils.get_files_from_path(unpackdir + "/rootfs")
#        with open(unpackdir + "/anchore_allfiles.json", 'w') as OFH:
#            OFH.write(json.dumps(allfiles))
#
#    print "init: " + str(time.time() - timer)
#    timer = time.time()
#    for name in allfiles.keys():
#        if allfiles[name]['type'] == 'file':
#            thefile = '/'.join([unpackdir, "rootfs", name])
#
#            if name not in outfiles_md5:
#                cmd = ["md5sum", thefile]
#                try:
#                    out = subprocess.check_output(cmd)
#                    (csum, other) = re.match("(\S*)\s*(\S*)", out).group(1, 2)
#                    outfiles_md5[name] = csum
#                except:
#                    outfiles_md5[name] = "DIRECTORY_OR_OTHER"
#
#            if name not in outfiles_sha256:
#                cmd = ["sha256sum", thefile]
#                try:
#                    out = subprocess.check_output(cmd)
#                    (csum, other) = re.match("(\S*)\s*(\S*)", out).group(1, 2)
#                    outfiles_sha256[name] = csum
#                except:
#                    outfiles_sha256[name] = "DIRECTORY_OR_OTHER"
#        else:
#            outfiles_md5[name] = "DIRECTORY_OR_OTHER"
#            outfiles_sha256[name] = "DIRECTORY_OR_OTHER"
#
#    print "process: " + str(time.time() - timer)

    timer = time.time()
    tar = tarfile.open(unpackdir + "/squashed.tar")
    for member in tar.getmembers():
        name = member.name
        if member.isfile():
            thefile = '/'.join([unpackdir, "rootfs", name])

            cmd = ["md5sum", thefile]
            try:
                out = subprocess.check_output(cmd)
                (csum, other) = re.match("(\S*)\s*(\S*)", out).group(1, 2)
                outfiles_md5[name] = csum
            except:
                outfiles_md5[name] = "DIRECTORY_OR_OTHER"

            cmd = ["sha256sum", thefile]
            try:
                out = subprocess.check_output(cmd)
                (csum, other) = re.match("(\S*)\s*(\S*)", out).group(1, 2)
                outfiles_sha256[name] = csum
            except:
                outfiles_sha256[name] = "DIRECTORY_OR_OTHER"
        else:
            outfiles_md5[name] = "DIRECTORY_OR_OTHER"
            outfiles_sha256[name] = "DIRECTORY_OR_OTHER"
        tar.close()

except Exception as err:
    print "ERROR: " + str(err)

if outfiles_md5:
    ofile = os.path.join(outputdir, 'files.md5sums')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outfiles_md5)

if outfiles_sha256:
    ofile = os.path.join(outputdir, 'files.sha256sums')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outfiles_sha256)


sys.exit(0)
