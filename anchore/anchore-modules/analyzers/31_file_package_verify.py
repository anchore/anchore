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
import copy

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

meta = anchore.anchore_utils.get_distro_from_path('/'.join([unpackdir, "rootfs"]))
distrodict = anchore.anchore_utils.get_distro_flavor(meta['DISTRO'], meta['DISTROVERS'], likedistro=meta['LIKEDISTRO'])
flavor = distrodict['flavor']

record = {'digest': None, 'md5': None, 'mode': None, 'group': None, 'user': None, 'size': None, 'package': None}
result = {}
resultlist = {}

if flavor == "RHEL":
    try:
        rpmdbdir = anchore.anchore_utils.rpm_prepdb(unpackdir)
    except:
        rpmdbdir = os.path.join(unpackdir, 'rootfs', 'var', 'lib', 'rpm')

    cmd = ['rpm', '--dbpath='+rpmdbdir, '-qa', '--queryformat', '"[%{FILENAMES}|ANCHORETOK|%{FILEDIGESTS}|ANCHORETOK|%{FILEMD5S}|ANCHORETOK|%{FILEMODES}|ANCHORETOK|%{FILEGROUPNAME}|ANCHORETOK|%{FILEUSERNAME}|ANCHORETOK|%{FILESIZES}|ANCHORETOK|%{=NAME}\n]"']
    try:
        pipes = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        o, e = pipes.communicate()
        exitcode = pipes.returncode
        soutput = o
        serror = e
        
        if exitcode == 0:
            for l in soutput.splitlines():
                l = l.strip()
                try:
                    (fname, fdigest, fmd5, fmode, fgroup, fuser, fsize, fpackage)= l.split("|ANCHORETOK|")
                    result[fname] = copy.deepcopy(record)
                    result[fname].update({'digest': fdigest, 'md5': fmd5, 'mode': fmode, 'group': fgroup, 'user': fuser, 'size': fsize, 'package': fpackage})
                except Exception as err:
                    print "WARN: unparsable output line - exception: " + str(err)

    except Exception as err:
        print "WARN: distro package metadata gathering failed - exception: " + str(err)

elif flavor == 'DEB':
    pass
else:
    # do nothing, distro not supported
    pass

if result:
    for f in result.keys():
        try:
            resultlist[f] = json.dumps(result[f], sort_keys=True)
        except:
            resultlist[f] = ""

if resultlist:
    ofile = os.path.join(outputdir, 'distro.pkgfilemeta')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, resultlist)

# now run the distro package verifier, if present

verify_result = {}
verifylist = {}

try:
    verify_result, voutput, verror, vexitcode = anchore.anchore_utils.verify_file_packages(unpackdir, flavor)
except Exception as err:
    print "WARN: could not run distro package verifier - exception: " + str(err)

if verify_result:
    for f in verify_result.keys():
        try:
            verifylist[f] = json.dumps(verify_result[f])
        except:
            verifylist[f] = ""

if verifylist:
    ofile = os.path.join(outputdir, 'distro.verifyresult')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, verifylist)
    
