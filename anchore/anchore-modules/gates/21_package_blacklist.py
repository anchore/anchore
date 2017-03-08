#!/usr/bin/env python

import sys
import os
import json
import re
import anchore
from anchore import anchore_utils
from anchore import anchore_image

gate_name = "PKGBLACKLIST"
triggers = {
    'PKGFULLMATCH':
    {
        'description':'triggers if the evaluated image has a package installed that matches one in the list given as a param (package_name|vers)',
        'params':'BLACKLIST_FULLMATCH'
    },
    'PKGNAMEMATCH':
    {
        'description':'triggers if the evaluated image has a package installed that matches one in the list given as a param (package_name)',
        'params':'BLACKLIST_NAMEMATCH'
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
# do somthing
try:
    image = anchore.anchore_image.AnchoreImage(imgid, allimages={})

    for pstr in params:
        try:
            (pkey, pvallist) = pstr.split("=")
            if pkey == 'BLACKLIST_FULLMATCH':
                for pval in pvallist.split(","):
                    try:
                        (pkg, vers) = pval.split("|")
                        ipkgs = image.get_allpkgs()
                        if pkg in ipkgs and vers == ipkgs[pkg]:
                            outlist.append('PKGFULLMATCH Package is blacklisted: '+pkg+"-"+vers)
                    except:
                        pass

            elif pkey == 'BLACKLIST_NAMEMATCH':
                for pval in pvallist.split(","):
                    try:
                        pkg = pval
                        ipkgs = image.get_allpkgs()
                        if pkg in ipkgs:
                            outlist.append('PKGNAMEMATCH Package is blacklisted: '+pkg)
                    except:
                        pass
            elif pkey == 'BLACKLIST_VERSIONLESSTHAN':
                print "THIS IS NOT IMPLEMENTED YET"
                sys.exit(1)
                # not implemented
        except Exception as err:
            # couldn't parse param string
            pass
except Exception as err:
    import traceback
    traceback.print_exc()
    print "ERROR: could not do something" + str(err)
    sys.exit(1)

# write output
#output = '/'.join([outputdir, gate_name])
anchore.anchore_utils.save_gate_output(imgid, gate_name, outlist)

#anchore.anchore_utils.write_kvfile_fromlist(output, outlist)

sys.exit(0)
