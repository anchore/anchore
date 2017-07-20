#!/usr/bin/env python

import sys
import os
import json
import re
import anchore
from anchore import anchore_utils
from anchore import anchore_image

gate_name = "LICBLACKLIST"
triggers = {
    'LICFULLMATCH':
    {
        'description':'triggers if the evaluated image has a package installed with software distributed under the specified (exact match) license(s)',
        'params':'LICBLACKLIST_FULLMATCH'
    },
    'LICSUBMATCH':
    {
        'description':'triggers if the evaluated image has a package installed with software distributed under the specified (substring match) license(s)',
        'params':'LICBLACKLIST_SUBMATCH'
    },
}
try:
    config = anchore.anchore_utils.init_gate_cmdline(sys.argv, gate_name, gate_help=triggers)
except Exception as err:
    import traceback
    traceback.print_exc()
    print str(err)
    sys.exit(1)

if not config:
    print "ERROR: could not set up environment for gate"
    sys.exit(1)

imgid = config['imgid']
#outputdir = config['dirs']['outputdir']

try:
    params = config['params']
except:
    params = None

if not params:
    sys.exit(0)

outlist = list()

fullmatch = False
fullmatchpkgs = list()

submatch = False
submatchpkgs = list()

# do somthing
try:
    pkgdetail_data = anchore_utils.load_analysis_output(imgid, 'package_list', 'pkgs.allinfo')

    # try to load up non distro package types as well
    for ptype in ['npm', 'gem']:
        try:
            pkgdetail_data_extra = anchore_utils.load_analysis_output(imgid, 'package_list', 'pkgs.'+ptype+'s')
            for pkg in pkgdetail_data_extra.keys():
                pkgjson = json.loads(pkgdetail_data_extra[pkg])
                pkgkey = pkgjson['name'] + "("+ptype+")"
                pkgdetail_data[pkgkey] = pkgdetail_data_extra[pkg]
        except Exception as err:
            pass

    pkgdetail = {}
    pkglics = {}
    for k in pkgdetail_data.keys():
        pkgdata = json.loads(pkgdetail_data[k])
        if 'license' in pkgdata:
            lics = pkgdata['license'].split()
        elif 'lics' in pkgdata:
            lics = pkgdata['lics']
        else:
            lics = []        
        pkglics[k] = lics

    for pstr in params:
        try:
            (pkey, pvallist) = pstr.split("=")
            if pkey == 'LICBLACKLIST_FULLMATCH':
                for pval in pvallist.split(","):
                    for pkg in pkglics.keys():
                        try:
                            if pval in pkglics[pkg]:
                                fullmatch = True
                                fullmatchpkgs.append(pkg+"("+pval+")")
                        except Exception as err:
                            print "ERR pval check: ("+pkg+"): " + str(err)
                            pass
            elif pkey == 'LICBLACKLIST_SUBMATCH':
                for pval in pvallist.split(","):
                    for pkg in pkglics.keys():
                        try:
                            for lic in pkglics[pkg]:
                                if re.match(".*"+re.escape(pval)+".*", lic):
                                    submatch = True
                                    submatchpkgs.append(pkg+"("+pval+")")
                                    #submatchpkgs.append(pkg+"("+lic+")")
                        except Exception as err:
                            print "ERR pval check: ("+ pkg + "): " + str(err)
                            pass
        except Exception as err:
            # couldn't parse param string
            print "ERR param exception: " + str(err)
            pass
    if fullmatch:
        outlist.append('LICFULLMATCH Packages are installed that have blacklisted licenses: '+', '.join(fullmatchpkgs))
    if submatch:
        outlist.append('LICSUBMATCH Packages are installed that have blacklisted licenses: '+', '.join(submatchpkgs))

except Exception as err:
    import traceback
    traceback.print_exc()
    print "ERROR: could not do something" + str(err)
    sys.exit(1)

# write output
anchore.anchore_utils.save_gate_output(imgid, gate_name, outlist)

sys.exit(0)
