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

import anchore.anchore_utils

def rpm_check_file_membership_from_path(inpath, allfiles=None):
    rpmfiles = {}
    matchfiles = list()
    nonmatchfiles = list()
    realnonmatchfiles = list()

    if not allfiles:
        filemap, allfiles = anchore.anchore_utils.get_files_from_path(inpath)

    real_root = os.open('/', os.O_RDONLY)
    try:
        os.chroot(inpath)

        # get a list of all files from RPM
        try:
            sout = subprocess.check_output(['rpm', '-qal'])
            sout = sout.decode('utf8')
        except subprocess.CalledProcessError as err:
            sout = ""
            errmsg = err.output.decode('utf8')

        for l in sout.splitlines():
            l = l.strip()
            rpmfiles[l] = True
    except Exception as err:
        print str(err)

    # find any rpm files that are not in the filesystem (first past)
    for rfile in allfiles.keys():
        if rfile not in rpmfiles:
            nonmatchfiles.append(rfile)

    # second pass - hardlinks make this necessary
    done=False
    start = 0
    while not done:
        cmdlist = nonmatchfiles[start:start+256]
        if len(cmdlist) <= 0:
            done=True
        else:
            try:
                sout = subprocess.check_output(['rpm', '-qf'] + cmdlist)
                sout = sout.decode('utf8')
            except subprocess.CalledProcessError as err:
                sout = err.output.decode('utf8')

            for l in sout.splitlines():
                l = l.strip()
                try:
                    filename = re.match("file (.*) is not owned by any package", l).group(1)
                    realnonmatchfiles.append(filename)
                except:
                    pass
        start = start + 256

    os.fchdir(real_root)
    os.chroot('.')
    
    # for all files, if not unmatched, consider them matched to a package
    for rfile in allfiles.keys():
        if rfile not in realnonmatchfiles:
            matchfiles.append(rfile)

    print "RESULT: " + str(len(matchfiles)) + " : " + str(len(realnonmatchfiles))
    return(matchfiles, realnonmatchfiles)

def rpm_check_file_membership_from_path_orig(inpath, allfiles=None):
    matchfiles = list()
    nonmatchfiles = list()

    if not allfiles:
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
    print "RESULT: " + str(len(matchfiles)) + " : " + str(len(nonmatchfiles))
    return(matchfiles, nonmatchfiles)

def dpkg_check_file_membership_from_path(inpath, allfiles=None):
    matchfiles = list()
    nonmatchfiles = list()

    if not allfiles:
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

    print "RESULT: " + str(len(matchfiles)) + " : " + str(len(nonmatchfiles))

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

simplefiles = {}
outfiles = {}
nonpkgoutfiles = {}
import time
timer = time.time()
try:
    allfiles = {}
    if os.path.exists(unpackdir + "/anchore_allfiles.json"):
        with open(unpackdir + "/anchore_allfiles.json", 'r') as FH:
            allfiles = json.loads(FH.read())
    else:
        fmap, allfiles = anchore.anchore_utils.get_files_from_path(unpackdir + "/rootfs")
        with open(unpackdir + "/anchore_allfiles.json", 'w') as OFH:
            OFH.write(json.dumps(allfiles))

    # fileinfo
    for name in allfiles.keys():
        outfiles[name] = json.dumps(allfiles[name])
        simplefiles[name] = oct(stat.S_IMODE(allfiles[name]['mode']))

    if distrodict['flavor'] == "RHEL":
        # rpm file check
        match, nonmatch = rpm_check_file_membership_from_path(unpackdir + "/rootfs", allfiles=allfiles)
        for f in nonmatch:
            nonpkgoutfiles[f] = 'NOTPKGED'
    elif distrodict['flavor'] == "DEB":
        # dpkg file check
        match, nonmatch = dpkg_check_file_membership_from_path(unpackdir + "/rootfs", allfiles=allfiles)
        for f in nonmatch:
            nonpkgoutfiles[f] = 'NOTPKGED'

except Exception as err:
    print "ERROR: " + str(err)

if simplefiles:
    ofile = os.path.join(outputdir, 'files.all')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, simplefiles)

if outfiles:
    ofile = os.path.join(outputdir, 'files.allinfo')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outfiles)
if nonpkgoutfiles:
    ofile = os.path.join(outputdir, 'files.nonpkged')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, nonpkgoutfiles)

sys.exit(0)
