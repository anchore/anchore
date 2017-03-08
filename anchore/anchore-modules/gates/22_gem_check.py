#!/usr/bin/env python

import sys
import os
import json
import re
import anchore

from anchore import anchore_utils
from anchore import anchore_feeds

gate_name = "GEMCHECK"
triggers = {
    'GEMNOTLATEST':
    {
        'description':'triggers if an installed GEM is not the latest version according to GEM data feed',
        'params':'None'
    },
    'GEMNOTOFFICIAL':
    {
        'description':'triggers if an installed GEM is not present in the official GEM repository, according to GEM data feed',
        'params':'None'
    },
    'GEMBADVERSION':
    {
        'description':'triggers if an installed GEM version is not listed in the official GEM feed as a valid version',
        'params':'None'
    },
    'GEMPKGFULLMATCH':
    {
        'description':'triggers if the evaluated image has an GEM package installed that matches one in the list given as a param (package_name|vers)',
        'params':'BLACKLIST_GEMFULLMATCH'
    },
    'GEMPKGNAMEMATCH':
    {
        'description':'triggers if the evaluated image has an GEM package installed that matches one in the list given as a param (package_name)',
        'params':'BLACKLIST_GEMNAMEMATCH'
    },
    'GEMNOFEED':
    {
        'description':'triggers if anchore does not have access to the GEM data feed',
        'params':'None'
    }
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

try:
    params = config['params']
except:
    params = None

if not params:
    sys.exit(0)


outlist = list()
# do somthing
try:
    pkgdetail_data = anchore.anchore_utils.load_analysis_output(imgid, 'package_list', 'pkgs.gems')
    if pkgdetail_data:
        feeddata = anchore.anchore_feeds.load_anchore_feed('packages', 'gem', ensure_unique=True)
        if feeddata and 'success' in feeddata and feeddata['success']:
            feeds = {}
            for el in feeddata['data']:
                pname = el.keys()[0]
                feeds[pname] = el[pname]

        else:
            feeds = {}
            outlist.append("GEMNOFEED GEM packages are present but the anchore GEM feed is not available - will be unable to perform checks that require feed data")
            outlist.append("GEMNOTLATEST GEM packages are present but the anchore GEM feed is not available - will be unable to perform GEMNOTLATEST policy checks")
            outlist.append("GEMNOTOFFICIAL GEM packages are present but the anchore GEM feed is not available - will be unable to perform GEMNOTOFFICIAL policy checks")
            outlist.append("GEMBADVERSION GEM packages are present but the anchore GEM feed is not available - will be unable to perform GEMBADVERSION policy checks")

        pkgs = {}
        for fname in pkgdetail_data.keys():
            pkgdetail = json.loads(pkgdetail_data[fname])
            pname = pkgdetail['name']
            if pname not in pkgs:
                pkgs[pname] = list()
            pkgs[pname] = pkgs[pname] + pkgdetail['versions']
            if feeds and pname in feeds:
                if feeds[pname]['latest']:
                    for v in pkgs[pname]:
                        if v in feeds[pname]['versions'] and v != feeds[pname]['latest']:
                            outlist.append("GEMNOTLATEST Package ("+pname+") version ("+v+") installed but is not the latest version ("+feeds[pname]['latest']+")")
                        elif v not in feeds[pname]['versions']:
                            outlist.append("GEMBADVERSION Package ("+pname+") version ("+v+") installed but version is not in the official feed for this package ("+str(feeds[pname]['versions']) + ")")
            elif feeds and pname not in feeds:
                outlist.append("GEMNOTOFFICIAL Package ("+str(pname)+") in container but not in official GEM feed.")

        for pstr in params:
            try:
                (pkey, pvallist) = pstr.split("=")
                if pkey == 'BLACKLIST_GEMFULLMATCH':
                    for pval in pvallist.split(","):
                        try:
                            (pkg, vers) = pval.split("|")
                            if pkg in pkgs and vers in pkgs[pkg]:
                                outlist.append('GEMPKGFULLMATCH Package is blacklisted: '+pkg+"-"+vers)
                        except:
                            pass

                elif pkey == 'BLACKLIST_GEMNAMEMATCH':
                    for pval in pvallist.split(","):
                        try:
                            pkg = pval
                            if pkg in pkgs:
                                outlist.append('GEMPKGNAMEMATCH Package is blacklisted: '+pkg)
                        except:
                            pass
            except Exception as err:
                # couldn't parse param string
                pass
except Exception as err:
    import traceback
    traceback.print_exc()
    print "ERROR: Exception: " + str(err)
    sys.exit(1)

# write output

anchore.anchore_utils.save_gate_output(imgid, gate_name, outlist)

sys.exit(0)
