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

#imgname = sys.argv[1]
#datadir = sys.argv[2]
#imgdatadir = sys.argv[3]
#unpackdir = sys.argv[4]
#outputdir = imgdatadir + "/analyzer_output/" + analyzer_name

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
CFH=open(outputdir + "/pkgs_plus_source.all", 'w')

if flav == "RHEL":
    try:
        rpm.addMacro("_dbpath", unpackdir + "/rootfs/var/lib/rpm")
        ts = rpm.TransactionSet()
        mi = ts.dbMatch()
        for h in mi:
            FH.write(h['name'] + " " + h['version'] + "-" + h['release'] + "\n")
    except:
        try:
            sout = subprocess.check_output(['chroot', unpackdir + '/rootfs', 'rpm', '--queryformat', '%{NAME} %{VERSION}-%{RELEASE}\n', '-qa'])
            for l in sout.splitlines():
                l = l.strip()
                FH.write(l + "\n")
        except:
            pass
elif flav == "DEB":
    actual_packages = {}
    all_packages = {}
    other_packages = {}
    cmd = ["dpkg-query", "--admindir="+unpackdir+"/rootfs/var/lib/dpkg", "-W", "-f="+"${Package} ${Version} ${source:Package} ${source:Version}\\n"]
    try:
        sout = subprocess.check_output(cmd)
        for l in sout.splitlines(True):
            l = l.strip()
            (p, v, sp, sv) = re.match('(\S*)\s*(\S*)\s*(\S*)\s*(.*)', l).group(1, 2, 3, 4)
            if p and v:
                if p not in actual_packages:
                    actual_packages[p] = v
                if p not in all_packages:
                    all_packages[p] = v
            if sp and sv:
                if sp not in all_packages:
                    all_packages[sp] = sv
            if p and v and sp and sv:
                if p == sp and v != sv:
                    other_packages[p] = [sv]

    except Exception as err:
        print "Could not run command: " + str(cmd)
        print "Exception: " + str(err)
        print "Please ensure the command 'dpkg' is available and try again"
        raise err

    for p in actual_packages.keys():
        FH.write(' '.join([p, actual_packages[p], '\n']))
        
    for p in all_packages.keys():
        CFH.write(' '.join([p, all_packages[p], '\n']))

    if len(other_packages) > 0:
        for p in other_packages.keys():
            for v in other_packages[p]:
                CFH.write(' '.join([p, v, '\n']))

elif flav == "BUSYB":
    FH.write("BusyBox " + meta['DISTROVERS'] + "\n")
else:
    FH.write("Unknown 0\n")
FH.close()
CFH.close()
