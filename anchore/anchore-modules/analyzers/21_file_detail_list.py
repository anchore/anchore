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

def rpm_check_file_membership_from_path(inpath):
    matchfiles = list()
    nonmatchfiles = list()

    filemap, allfiles = anchore.anchore_utils.get_files_from_path(inpath)

    real_root = os.open('/', os.O_RDONLY)
    try:
        os.chroot(inpath)
        try:
            sout = subprocess.check_output(['rpm', '-qf'] + allfiles.keys())
            sout = sout.decode('utf8')
        except subprocess.CalledProcessError as err:
            sout = err.output.decode('utf8')

        for l in sout.splitlines():
            l = l.strip()
            try:
                filename = re.match("file (.*) is not owned by any package", l).group(1)
                nonmatchfiles.append(filename)
            except:
                pass
    except Exception as err:
        print str(err)

    os.fchdir(real_root)
    os.chroot('.')

    matchfiles = list(set(allfiles.keys()) - set(nonmatchfiles))
    return(matchfiles, nonmatchfiles)

def dpkg_check_file_membership_from_path(inpath):
    matchfiles = list()
    nonmatchfiles = list()

    filemap, allfiles = anchore.anchore_utils.get_files_from_path(inpath)

    real_root = os.open('/', os.O_RDONLY)
    try:
        os.chroot(inpath)
        for flist in anchore.anchore_utils.grouper(allfiles.keys(), 256):
            try:
                sout = subprocess.check_output(['dpkg', '-S'] + flist, stderr=subprocess.STDOUT)
                sout = sout.decode('utf8')
            except subprocess.CalledProcessError as err:
                sout = err.output.decode('utf8')

            for l in sout.splitlines():
                l = l.strip()
                try:
                    filename = re.match("dpkg-query: no path found matching pattern (.*)", l).group(1)
                    nonmatchfiles.append(filename)
                except:
                    pass

    except Exception as err:
        print str(err)

    os.fchdir(real_root)
    os.chroot('.')

    matchfiles = list(set(allfiles.keys()) - set(nonmatchfiles))
    return(matchfiles, nonmatchfiles)

analyzer_name = "file_list"

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

meta = anchore.anchore_utils.get_distro_from_path('/'.join([unpackdir, "rootfs"]))
distrodict = anchore.anchore_utils.get_distro_flavor(meta['DISTRO'], meta['DISTROVERS'], meta['LIKEDISTRO'])

outfiles = {}
nonpkgoutfiles = {}

try:
    fmap, allfiles = anchore.anchore_utils.get_files_from_path(unpackdir + "/rootfs")

    # fileinfo
    for name in allfiles.keys():
        outfiles[name] = json.dumps(allfiles[name])

    if distrodict['flavor'] == "RHEL":
        # rpm file check
        match, nonmatch = rpm_check_file_membership_from_path(unpackdir + "/rootfs")
        for f in nonmatch:
            nonpkgoutfiles[f] = 'NOTPKGED'
    elif distrodict['flavor'] == "DEB":
        # dpkg file check
        match, nonmatch = dpkg_check_file_membership_from_path(unpackdir + "/rootfs")
        for f in nonmatch:
            nonpkgoutfiles[f] = 'NOTPKGED'

except Exception as err:
    print "ERROR: " + str(err)

if outfiles:
    ofile = os.path.join(outputdir, 'files.allinfo')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outfiles)
if nonpkgoutfiles:
    ofile = os.path.join(outputdir, 'files.nonpkged')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, nonpkgoutfiles)

sys.exit(0)
