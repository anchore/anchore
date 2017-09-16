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

def deb_get_file_package_metadata(unpackdir, record_template):

    result = {}
    metafiles = {}
    metapath = os.path.join(unpackdir, "rootfs", "var", "lib", "dpkg", "info")

    try:
        if os.path.exists(metapath):
            for f in os.listdir(metapath):
                patt = re.match("(.*)\.md5sums", f)
                if patt:
                    pkgraw = patt.group(1)
                    patt = re.match("(.*):.*", pkgraw)
                    if patt:
                        pkg = patt.group(1)
                    else:
                        pkg = pkgraw

                    metafiles[pkg] = os.path.join(metapath, f)
        else:
            raise Exception("no dpkg info path found in image: " + str(metapath))

        for pkg in metafiles.keys():
            dinfo = None
            with open(metafiles[pkg], 'r') as FH:
                dinfo = FH.read()

            if dinfo:
                for line in dinfo.splitlines():
                    line.strip()
                    (csum, fname) = line.split()
                    fname = '/' + fname
                    fname = re.sub("\/\/", "\/", fname)
                    if fname in result:
                        print "WARNING: meta file name collision: " + str(fname)
                    result[fname] = copy.deepcopy(record_template)
                    result[fname].update({"package": pkg or None, "md5": csum or None, "digest": csum or None, "digestalgo": "md5"})

    except Exception as err:
        raise Exception("WARN: could not find/parse dpkg info metadata files - exception: " + str(err))

    return(result)

def rpm_get_file_package_metadata(unpackdir, record_template):
    result = {}

    try:
        rpmdbdir = anchore.anchore_utils.rpm_prepdb(unpackdir)
    except:
        rpmdbdir = os.path.join(unpackdir, 'rootfs', 'var', 'lib', 'rpm')

    cmdstr = 'rpm --dbpath='+rpmdbdir+' -qa --queryformat "[%{FILENAMES}|ANCHORETOK|%{FILEDIGESTS}|ANCHORETOK|%{FILEMD5S}|ANCHORETOK|%{FILEMODES}|ANCHORETOK|%{FILEGROUPNAME}|ANCHORETOK|%{FILEUSERNAME}|ANCHORETOK|%{FILESIZES}|ANCHORETOK|%{=NAME}|ANCHORETOK|%{FILEFLAGS:fflags}\\n]"'
    cmd = cmdstr.split()
    print cmdstr
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
                    (fname, fdigest, fmd5, fmode, fgroup, fuser, fsize, fpackage, fflags)= l.split("|ANCHORETOK|")

                    cfile = False
                    if 'c' in str(fflags):
                        cfile = True

                    result[fname] = copy.deepcopy(record_template)
                    result[fname].update({'digest': fdigest or None, 'digestalgo': 'sha256', 'md5': fmd5 or None, 'mode': fmode or None, 'group': fgroup or None, 'user': fuser or None, 'size': fsize or None, 'package': fpackage or None, 'conffile': cfile})
                except Exception as err:
                    print "WARN: unparsable output line - exception: " + str(err)
        else:
            raise Exception("rpm file metadata command failed with exitcode ("+str(exitcode)+") - stdoutput: " + str(soutput) + " : stderr: " + str(serror))

    except Exception as err:
        raise Exception("WARN: distro package metadata gathering failed - exception: " + str(err))

    return(result)

analyzer_name = "file_package_verify"

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

# gather file metadata from installed packages

record = {'digest': None, 'digestalgo': None, 'md5': None, 'mode': None, 'group': None, 'user': None, 'size': None, 'package': None, 'conffile': False}
result = {}
resultlist = {}

if flavor == "RHEL":
    try:
        result = rpm_get_file_package_metadata(unpackdir, record)
    except Exception as err:
        print "WARN: " + str(err)

elif flavor == 'DEB':
    try:
        result = deb_get_file_package_metadata(unpackdir, record)
    except Exception as err:
        print "WARN: " + str(err)        
else:
    # do nothing, flavor not supported for getting metadata about files from pkg manager
    pass

if result:
    for f in result.keys():
        try:
            resultlist[f] = json.dumps(result[f], sort_keys=True)
        except Exception as err:
            print "WARN: " + str(err)
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
    
sys.exit(0)
