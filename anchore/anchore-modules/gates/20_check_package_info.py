#!/usr/bin/env python

import sys
import os
import re
import json
import anchore.anchore_utils

gate_name = "PKGCHECK"
triggers = {
    'PKGNOTPRESENT':
    {
        'description':'triggers if the package(s) specified in the params are not installed in the container image.  PKGFULLMATCH param can specify an exact match (ex: "curl|7.29.0-35.el7.centos").  PKGNAMEMATCH param can specify just the package name (ex: "curl").  PKGVERSMATCH can specify a minimum version and will trigger if installed version is less than the specified minimum version (ex: zlib|0.2.8-r2)',
        'params':'PKGFULLMATCH,PKGNAMEMATCH,PKGVERSMATCH'
    }
}


try:
    config = anchore.anchore_utils.init_gate_cmdline(sys.argv, gate_name, gate_help=triggers)
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

imgid = config['imgid']

params = []
try:
    params = config['params']
except:
    params = None

if not params:
    sys.exit(0)

fullmatch = {}
namematch = {}
vermatch = {}

for param in params:
    try:
        (p,v) = param.split("=")
        for pkgstring in v.split(","):
            try:
                try:
                    (pkg, vers) = pkgstring.split("|")
                except:
                    pkg = pkgstring
                    vers = None
                if p == 'PKGFULLMATCH':
                    fullmatch[pkg] = vers
                elif p == 'PKGNAMEMATCH':
                    namematch[pkg] = True
                elif p == 'PKGVERSMATCH':
                    vermatch[pkg] = vers
            except Exception as err:
                raise err
    except Exception as err:
        print "WARN: input param could not be parsed out, skipping: " + str(param)

outlist = list()
imageId = config['imgid']

norm_packages = anchore.anchore_utils.normalize_packages(imageId)
bin_packages = norm_packages['bin_packages']

for pkg in fullmatch:
    if pkg in bin_packages:
        try:
            if bin_packages[pkg]['fullvers'] != fullmatch[pkg]:
                outlist.append("PKGNOTPRESENT input package ("+str(pkg)+") is present ("+str(bin_packages[pkg]['fullvers'])+"), but not at the version specified in policy ("+str(fullmatch[pkg])+")")
        except:
            pass
    else:
        outlist.append("PKGNOTPRESENT input package ("+str(pkg)+"-"+str(fullmatch[pkg])+") is not present in container image")

for pkg in namematch:
    if pkg not in bin_packages:
        outlist.append("PKGNOTPRESENT input package ("+str(pkg)+") is not present in container image")

for pkg in vermatch:
    if pkg in bin_packages:
        if bin_packages[pkg]['fullvers'] != vermatch[pkg]:
            rc = anchore.anchore_utils.compare_package_versions(imageId, pkg, bin_packages[pkg]['fullvers'], pkg, vermatch[pkg])
            if rc < 0:
                outlist.append("PKGNOTPRESENT input package ("+str(pkg)+") is present ("+str(bin_packages[pkg]['fullvers'])+"), but is lower version than what is specified in policy ("+str(vermatch[pkg])+")")
    else:
        outlist.append("PKGNOTPRESENT input package ("+str(pkg)+"-"+str(vermatch[pkg])+") is not present in container image")

anchore.anchore_utils.save_gate_output(imageId, gate_name, outlist)

sys.exit(0)
