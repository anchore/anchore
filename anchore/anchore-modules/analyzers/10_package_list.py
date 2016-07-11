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

analyzer_name = "package_list"

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

metafile = unpackdir + "/analyzer_meta"
meta = {"DISTRO":"Unknown", "DISTROVERS":"0", "LIKEDISTRO":"Unknown"}
meta.update(anchore.anchore_utils.read_kvfile_todict(metafile))

if meta['DISTRO'] in ['centos', 'rhel'] or meta['LIKEDISTRO'] in ['centos', 'rhel']:
    flav = "RHEL"
elif meta['DISTRO'] in ['ubuntu', 'debian'] or meta['LIKEDISTRO'] in ['ubuntu','debian']:
    flav = "DEB"
elif meta['DISTRO'] in ['busybox'] or meta['LIKEDISTRO'] in ['busybox']:
    flav = 'BUSYB'
else:
    flav = "UNK"

FH=open(outputdir + "/pkgs.all", 'w')
FFH=open(outputdir + "/pkgfiles.all", 'w')
CFH=open(outputdir + "/pkgs_plus_source.all", 'w')

if flav == "RHEL":
    try:
        rpms = anchore.anchore_utils.rpm_get_all_packages(unpackdir)
        for pkg in rpms.keys():
            FH.write(pkg + " " + rpms[pkg]['version'] + "-" + rpms[pkg]['release'] + "\n")
    except Exception as err:
        print "WARN: failed to generate RPM package list: " + str(err)

    try:
        rpmfiles = anchore.anchore_utils.rpm_get_all_pkgfiles(unpackdir)
        for pkgfile in rpmfiles.keys():
            FFH.write(pkgfile + " RPMFILE\n")
    except Exception as err:
        print "WARN: failed to get file list from RPMs: " + str(err)

elif flav == "DEB":
    try:
        (all_packages, actual_packages, other_packages) = anchore.anchore_utils.dpkg_get_all_packages(unpackdir)
    
        for p in actual_packages.keys():
            FH.write(' '.join([p, actual_packages[p]['version'], '\n']))

        for p in all_packages.keys():
            CFH.write(' '.join([p, all_packages[p]['version'], '\n']))

        if len(other_packages) > 0:
            for p in other_packages.keys():
                for v in other_packages[p]:
                    CFH.write(' '.join([p, v['version'], '\n']))
    except Exception as err:
        print "WARN: failed to get package list from DPKG: " + str(err)

    try:
        dpkgfiles = anchore.anchore_utils.dpkg_get_all_pkgfiles(unpackdir)
        for pkgfile in dpkgfiles.keys():
            FFH.write(pkgfile + " DPKGFILE\n")

    except Exception as err:
        print "WARN: failed to get file list from DPKGs: " + str(err)

elif flav == "BUSYB":
    FH.write("BusyBox " + meta['DISTROVERS'] + "\n")
else:
    FH.write("Unknown 0\n")

FH.close()
FFH.close()
CFH.close()
