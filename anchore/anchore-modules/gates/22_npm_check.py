#!/usr/bin/env python

import sys
import os
import json
import re
import anchore

from anchore import anchore_utils
from anchore import anchore_feeds

gate_name = "NPMCHECK"
triggers = {
    'NPMNOTLATEST':
    {
        'description':'triggers if an installed NPM is not the latest version according to NPM data feed',
        'params':'None'
    },
    'NPMNOTOFFICIAL':
    {
        'description':'triggers if an installed NPM is not in the official NPM database, according to NPM data feed',
        'params':'None'
    },
    'NPMBADVERSION':
    {
        'description':'triggers if an installed NPM version is not listed in the official NPM feed as a valid version',
        'params':'None'
    },
    'NPMPKGFULLMATCH':
    {
        'description':'triggers if the evaluated image has an NPM package installed that matches one in the list given as a param (package_name|vers)',
        'params':'BLACKLIST_NPMFULLMATCH'
    },
    'NPMPKGNAMEMATCH':
    {
        'description':'triggers if the evaluated image has an NPM package installed that matches one in the list given as a param (package_name)',
        'params':'BLACKLIST_NPMNAMEMATCH'
    },
    'NPMNOFEED':
    {
        'description':'triggers if anchore does not have access to the NPM data feed',
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
    pkgdetail_data = anchore.anchore_utils.load_analysis_output(imgid, 'package_list', 'pkgs.npms')
    if pkgdetail_data:
        feeddata = anchore.anchore_feeds.load_anchore_feed('packages', 'npm', ensure_unique=True)
        if feeddata and 'success' in feeddata and feeddata['success']:
            feeds = {}
            for el in feeddata['data']:
                pname = el.keys()[0]
                feeds[pname] = el[pname]

        else:
            feeds = {}
            outlist.append("NPMNOFEED NPM packages are present but the anchore NPM feed is not available - will be unable to perform checks that require feed data")
            outlist.append("NPMNOTLATEST NPM packages are present but the anchore NPM feed is not available - will be unable to perform NPMNOTLATEST policy checks")
            outlist.append("NPMBADVERSION NPM packages are present but the anchore NPM feed is not available - will be unable to perform NPMBADVERSION policy checks")
            outlist.append("NPMNOTOFFICIAL NPM packages are present but the anchore NPM feed is not available - will be unable to perform NPMNOTOFFICIAL policy checks")

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
                            outlist.append("NPMNOTLATEST Package ("+pname+") version ("+v+") installed but is not the latest version ("+feeds[pname]['latest']+")")
                        elif v not in feeds[pname]['versions']:
                            outlist.append("NPMBADVERSION Package ("+pname+") version ("+v+") installed but version is not in the official feed for this package ("+str(feeds[pname]['versions']) + ")")
                        #if v != feeds[pname]['latest']:
                        #    outlist.append("NPMNOTLATEST Package ("+pname+") version ("+v+") installed but is not the latest version ("+feeds[pname]['latest']+")")
                        #if v in feeds[pname]['versions'] and v != feeds[pname]['latest']:
                        #    outlist.append("NPMNOTLATEST Package ("+pname+") version ("+v+") installed but is not the latest version ("+feeds[pname]['latest']+")")
                        #elif v not in feeds[pname]['versions']:
                        #    outlist.append("NPMBADVERSION Package ("+pname+") version ("+v+") installed but version is not in the official feed for this package ("+str(feeds[pname]['versions']) + ")")
            elif feeds and pname not in feeds:
                outlist.append("NPMNOTOFFICIAL Package ("+str(pname)+") in container but not in official NPM feed.")

        for pstr in params:
            try:
                (pkey, pvallist) = pstr.split("=")
                if pkey == 'BLACKLIST_NPMFULLMATCH':
                    for pval in pvallist.split(","):
                        try:
                            (pkg, vers) = pval.split("|")
                            if pkg in pkgs and vers in pkgs[pkg]:
                                outlist.append('NPMPKGFULLMATCH Package is blacklisted: '+pkg+"-"+vers)
                        except:
                            pass

                elif pkey == 'BLACKLIST_NPMNAMEMATCH':
                    for pval in pvallist.split(","):
                        try:
                            pkg = pval
                            if pkg in pkgs:
                                outlist.append('NPMPKGNAMEMATCH Package is blacklisted: '+pkg)
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
