#!/usr/bin/env python

import sys
import os
import json
import re
import rpm
from rpmUtils.miscutils import splitFilename
from anchore import anchore_image
import anchore.anchore_utils

gate_name = "ANCHORESEC"

try:
    config = anchore.anchore_utils.init_gate_cmdline(sys.argv, gate_name)
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    print "ERROR: could not set up environment for gate"
    sys.exit(1)

imgid = config['imgid']

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
    import traceback
    traceback.print_exc()
    print "ERROR: could not scan image for CVEs: " + str(err)
    outlist = list()
    outlist.append("UNSUPPORTEDDISTRO Cannot load CVE data for image distro to perform scan.")
    anchore.anchore_utils.save_gate_output(imgid, gate_name, outlist)
    sys.exit(0)

outlist = list()
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

    outlist.append(t + " " + sev + " Vulnerability found in package - " + pkg + " (" + cve + " - " + url + ")")

anchore.anchore_utils.save_gate_output(imgid, gate_name, outlist)

sys.exit(0)
