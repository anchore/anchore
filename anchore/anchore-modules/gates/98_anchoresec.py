#!/usr/bin/env python

import sys
import os
import json
import re
import rpm
from rpmUtils.miscutils import splitFilename
import deb_pkg_tools
from deb_pkg_tools.version import Version
from anchore import anchore_image
import anchore.anchore_utils

try:
    config = anchore.anchore_utils.init_gate_cmdline(sys.argv, "CVE Checking Gate")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    print "ERROR: could not set up environment for gate"
    sys.exit(1)

imgid = config['imgid']
imgdir = config['dirs']['imgdir']
analyzerdir = config['dirs']['analyzerdir']
comparedir = config['dirs']['comparedir']
outputdir = config['dirs']['outputdir']

try:
    params = config['params']
except:
    params = None

cvedirroot = '/'.join([config['anchore_config']['image_data_store'], "../cve-data"])

try:
    image = anchore_image.AnchoreImage(imgid, config['anchore_config']['image_data_store'], {})
    cve_data = anchore.anchore_utils.cve_load_data(cvedirroot, image)
    report = anchore.anchore_utils.cve_scanimage(cve_data, image)
except Exception as err:
    print "ERROR: could not scan image for CVEs: " + str(err)
    exit(1)

output = '/'.join([outputdir, 'ANCHORESEC'])
OFH=open(output, 'w')
for k in report.keys():
    vuln = report[k]
    cve = k
    pkg = vuln['pkgName']
    sev = vuln['severity']
    url = vuln['url']
    if sev == 'Low':
        t = "VULNLOW"
    elif sev == 'Medium':
        t = "VULNMEDIUM"
    elif sev == "High":
        t = "VULNHIGH"
    elif sev == "Critical":
        t = "VULNCRITICAL"
    else:
        t = "VULNUNKNOWN"

    OFH.write(t + " " + sev + " Vulnerability found in package - " + pkg + " (" + cve + " - " + url + ")\n")

OFH.close()
sys.exit(0)
