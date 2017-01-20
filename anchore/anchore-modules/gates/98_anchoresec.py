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
triggers = {
    'VULNLOW':
    {
        'description':'triggers if a vulnerability of LOW severity is found',
        'params':'none'
    },
    'VULNMEDIUM':
    {
        'description':'triggers if a vulnerability of MED severity is found',
        'params':'none'
    },
    'VULNHIGH':
    {
        'description':'triggers if a vulnerability of HIGH severity is found',
        'params':'none'
    },
    'VULNCRITICAL':
    {
        'description':'triggers if a vulnerability of CRITICAL severity is found',
        'params':'none'
    },
    'VULNUNKNOWN':
    {
        'description':'triggers if a vulnerability of UNKNOWN severity is found',
        'params':'none'
    },
    'UNSUPPORTEDDISTRO':
    {
        'description':'triggers if a vulnerability scan cannot be run against the image due to lack of vulnerability feed data for the images distro',
        'params':'none'
    },
}


try:
    config = anchore.anchore_utils.init_gate_cmdline(sys.argv, gate_name, gate_help=triggers)
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
    cve_data = anchore.anchore_utils.cve_load_data(image)
    report = anchore.anchore_utils.cve_scanimage(cve_data, imgid)
except Exception as err:
    import traceback
    traceback.print_exc()
    print "ERROR: could not scan image for CVEs: " + str(err)
    outlist = list()
    outlist.append("UNSUPPORTEDDISTRO Cannot load CVE data for image distro to perform scan. Message from service: "+str(err))
    anchore.anchore_utils.save_gate_output(imgid, gate_name, outlist)
    sys.exit(0)

outlist = list()
for k in report.keys():
    for cvepkg in report[k]:
        vuln = cvepkg
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

        d = {'id':cve, 'desc':sev + " Vulnerability found in package - " + pkg + " (" + cve + " - " + url + ")"}
        #outlist.append(t + " " + sev + " Vulnerability found in package - " + pkg + " (" + cve + " - " + url + ")")
        outlist.append(t + " " + json.dumps(d))

anchore.anchore_utils.save_gate_output(imgid, gate_name, outlist)

sys.exit(0)
