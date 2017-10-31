#!/usr/bin/env python

import sys
import os
import shutil
import re
import json
import time
import rpm
import subprocess
import stat
import tarfile
import time
import hashlib
import copy
import traceback
import pkg_resources
import zipfile

import anchore.anchore_utils

analyzer_name = "package_list"

try:
    config = anchore.anchore_utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print str(err)
    sys.exit(1)

imgname = config['imgid']
imgid = config['imgid_full']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

resultlist = {}
try:
    allfiles = {}
    if os.path.exists(unpackdir + "/anchore_allfiles.json"):
        with open(unpackdir + "/anchore_allfiles.json", 'r') as FH:
            allfiles = json.loads(FH.read())
    else:
        fmap, allfiles = anchore.anchore_utils.get_files_from_path(unpackdir + "/rootfs")
        with open(unpackdir + "/anchore_allfiles.json", 'w') as OFH:
            OFH.write(json.dumps(allfiles))

    for f in allfiles.keys():
        if allfiles[f]['type'] == 'file':
            patt = re.match(".*\.(jar|war|ear)", f)
            if patt:
                candidate = '/'.join([unpackdir, 'rootfs', f.encode('utf8')])
                prefix = '/'.join([unpackdir, 'rootfs'])
                jtype = patt.group(1)
                #print "JTYPE: " + str(jtype) + " : " + candidate

                if jtype in ['jar', 'war', 'ear']:
                    try:
                        el = {
                            'metadata':{},
                            'specification-version': "N/A",
                            'implementation-version': "N/A",
                            'origin': "N/A",
                            'location': "N/A",
                            'type': "N/A"
                        }
                        el['location'] = re.sub("^/*"+prefix+"/*", "/", candidate.decode('utf8'))
                        el['type'] = "java-"+str(jtype)
                        el['name'] = re.sub("\."+jtype+"$", "", candidate.split("/")[-1])

                        sname = sversion = svendor = iname = iversion = ivendor = mname = None

                        with zipfile.ZipFile(candidate, 'r') as ZFH:
                            with ZFH.open("META-INF/MANIFEST.MF", 'r') as MFH:
                                el['metadata']['MANIFEST.MF'] = MFH.read()

                                for line in el['metadata']['MANIFEST.MF'].splitlines():
                                    try:
                                        (k,v) = line.split(": ", 1)
                                        if k == 'Specification-Title':
                                            sname = v
                                        elif k == 'Specification-Version':
                                            sversion = v
                                        elif k == 'Specification-Vendor':
                                            svendor = v
                                        elif k == 'Implementation-Title':
                                            iname = v
                                        elif k == 'Implementation-Version':
                                            iversion = v
                                        elif k == 'Implementation-Vendor':
                                            ivendor = v
                                    except:
                                        pass

                                #if iversion:
                                #    if sversion:
                                #        el['version'] += re.sub("^"+sversion, "", iversion)
                                #    else:
                                #        el['version'] += iversion
                                #el['origin'] = "N/A"
                                #if ivendor:
                                #    el['origin'] = ivendor
                                #elif svendor:
                                #    el['origin'] = svendor

                                #for k in ['version', 'origin', 'location']:
                                #    if not el[k]:
                                #        el[k] = "N/A"
                                    
                                #if not el['version'] or el['version'] == "N/A":
                                #    try:
                                #        patt = re.match(".*-([0-9].*)$", el['name'])
                                #        if patt:
                                #            el['version'] = patt.group(1)
                        
                                #        pass
                                #el.pop('metadata', None)
                                #print "EL: " + str(el)

                        if sversion:
                            el['specification-version'] = sversion

                        if iversion:
                            el['implementation-version'] = iversion

                        if svendor:
                            el['origin'] = svendor
                        elif ivendor:
                            el['origin'] = ivendor
                        

                    except Exception as err:
                        print "WARN: cannot extract information about discovered jar (" + str(f) + ") - exception: " + str(err)
                        el = {}

                    if el:
                        resultlist[el['location']] = json.dumps(el)

except Exception as err:
    print "WARN: analyzer unable to complete - exception: " + str(err)

if resultlist:
    ofile = os.path.join(outputdir, 'pkgs.java')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, resultlist)

sys.exit(0)
