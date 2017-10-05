#!/usr/bin/env python

import sys
import os
import json
import re
import anchore 

from anchore import anchore_utils

gate_name = "SECRETCHECK"
triggers = {
    'CONTENTMATCH':
    {
        'description':'Triggers if the secret search analyzer has found any matches.  If the parameter is set, then will only trigger against found matches that are also in the SECRETCHECK_CONTENTREGEXP parameter list.  If the parameter is absent or blank, then the trigger will fire if the analyzer found any matches.',
        'params':'SECRETCHECK_CONTENTREGEXP'
    },
    'FILENAMEMATCH':
    {
        'description':'Triggers if a file exists in the container that matches with any of the regular expressions given as SECRETCHECK_NAMEREGEXP parameters.',
        'params':'SECRETCHECK_NAMEREGEXP'
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

imageId = config['imgid']

params = []
try:
    params = config['params']
except:
    params = None

content_regexps = list()
content_regexps_decoded = list()
fname_regexps = list()
if params:
    for param in params:
        try:
            patt = re.match("SECRETCHECK_CONTENTREGEXP=(.*)", param)
            if patt:
                value = patt.group(1)
                for regexp in value.split("|"):
                    content_regexps.append(regexp.encode('base64'))
                    content_regexps_decoded.append(regexp)

            patt = re.match("SECRETCHECK_NAMEREGEXP=(.*)", param)
            if patt:
                value = patt.group(1)
                for regexp in value.split("|"):
                    fname_regexps.append(regexp.encode('base64'))
        except Exception as err:
            print "ERROR: failure parsing parameter strings - exception: " + str(err)
            sys.exit(1)

outlist = list()
# look to see if the content search analyzer matched any files
try:
    results = anchore.anchore_utils.load_analysis_output(imageId, 'secret_search', 'regexp_matches.all')
    if results:
        for thefile in results.keys():
            data = json.loads(results[thefile])
            for b64regexp in data.keys():
                regexp = b64regexp.decode('base64')
                try:
                    regexp_name, theregexp = regexp.split("=", 1)
                except:
                    regexp_name = None
                    theregexp = regexp

                if b64regexp in content_regexps:
                    outlist.append("CONTENTMATCH file secret search analyzer found regexp match in container: file="+str(thefile) + " regexp="+str(regexp))
                elif theregexp in content_regexps_decoded:
                    outlist.append("CONTENTMATCH file secret search analyzer found regexp match in container: file="+str(thefile) + " thereg="+str(regexp))
                elif regexp_name and regexp_name in content_regexps_decoded:
                    outlist.append("CONTENTMATCH file secret search analyzer found regexp match in container: file="+str(thefile) + " regexp="+str(regexp))
                    
                
except Exception as err:
    print "ERROR: failure checking analyzer output - exception: " + str(err)
    sys.exit(1)

# look for files by name
try:
    results = anchore.anchore_utils.load_analysis_output(imageId, 'file_list', 'files.all')
    for thefile in results.keys():
        for b64regexp in fname_regexps:
            regexp = b64regexp.decode('base64')
            if re.match(regexp, thefile):
                outlist.append("FILENAMEMATCH application of regexp matched file found in container: file="+str(thefile) + " regexp="+str(regexp))
except Exception as err:
    import traceback
    traceback.print_exc()
    print "ERROR: failure checking file names - exception: " + str(err)
    sys.exit(1)

# write output
anchore.anchore_utils.save_gate_output(imageId, gate_name, outlist)

sys.exit(0)
