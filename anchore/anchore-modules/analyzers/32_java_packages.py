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
from io import BytesIO

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

def fuzzy_java(input_el):
    ret_names = []
    ret_versions = []

    iversion = input_el.get('implementation-version', "N/A")
    if iversion != 'N/A':
        ret_versions.append(iversion)

    sversion = input_el.get('specification-version', "N/A")
    if sversion != 'N/A':
        if sversion not in ret_versions:
            ret_versions.append(sversion)

    # do some heuristic tokenizing
    try:
        toks = re.findall("[^-]+", input_el['name'])
        firstname = None
        fullname = []
        firstversion = None
        fullversion = []

        doingname = True
        for tok in toks:
            if re.match("^[0-9]", tok):
                doingname = False

            if doingname:
                if not firstname:
                    firstname = tok
                else:
                    fullname.append(tok)
            else:
                if not firstversion:
                    firstversion = tok
                else:
                    fullversion.append(tok)

        if firstname:
            firstname_nonums = re.sub("[0-9].*$", "", firstname)
            for gthing in [firstname, firstname_nonums]:
                if gthing not in ret_names:
                    ret_names.append(gthing)
                if '-'.join([gthing]+fullname) not in ret_names:
                    ret_names.append('-'.join([gthing]+fullname))

        if firstversion:
            firstversion_nosuffix = re.sub("\.(RELEASE|GA)$", "", firstversion)
            for gthing in [firstversion, firstversion_nosuffix]:
                if gthing not in ret_versions:
                    ret_versions.append(gthing)
                if '-'.join([gthing]+fullversion) not in ret_versions:
                    ret_versions.append('-'.join([gthing]+fullversion))

    except Exception as err:
        pass
    
    return(ret_names, ret_versions)

def process_java_archive(prefix, filename, inZFH):
    ret = []

    
    fullpath = '/'.join([prefix, filename])

    jtype = None
    patt = re.match(".*\.(jar|war|ear)", fullpath)
    if patt:
        jtype = patt.group(1)
    else:
        return([])
    name = re.sub("\."+jtype+"$", "", fullpath.split("/")[-1])

    top_el = {}
    sub_els = []
    try:

        # set up the zipfile handle
        try:
            if not inZFH:
                if zipfile.is_zipfile(fullpath):
                    ZFH = zipfile.ZipFile(fullpath, 'r')
                    location = filename
                else:
                    return([])
            else:
                zdata = BytesIO( inZFH.read() )
                ZFH = zipfile.ZipFile(zdata, 'r')
                location = prefix + ":" + filename
    
        except Exception as err:
            raise err

        top_el = {
            'metadata':{},
            'specification-version': "N/A",
            'implementation-version': "N/A",
            'origin': "N/A",
            'location': "N/A",
            'type': "N/A"
        }
        top_el['location'] = location 
        top_el['type'] = "java-"+str(jtype)
        top_el['name'] = name

        sname = sversion = svendor = iname = iversion = ivendor = mname = None
    
        try:
            with ZFH.open('META-INF/MANIFEST.MF', 'r') as MFH:
                top_el['metadata']['MANIFEST.MF'] = MFH.read()

            for line in top_el['metadata']['MANIFEST.MF'].splitlines():
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

            if sversion:
                top_el['specification-version'] = sversion
            if iversion:
                top_el['implementation-version'] = iversion

            if svendor:
                top_el['origin'] = svendor
            elif ivendor:
                top_el['origin'] = ivendor

            try:
                guessed_names, guessed_versions = fuzzy_java(top_el)
            except:
                guessed_names = guessed_versions = []

            top_el['guessed_names'] = guessed_names
            top_el['guessed_versions'] = guessed_versions

        except:
            # no manifest could be parsed out, leave the el values unset
            pass

        for zfname in ZFH.namelist():
            sub_jtype = None
            patt = re.match(".*\.(jar|war|ear)", zfname)
            if patt:
                sub_jtype = patt.group(1)

            if sub_jtype:
                ZZFH = None
                try:
                    ZZFH = ZFH.open(zfname, 'r')
                    sub_els = sub_els + process_java_archive(location, zfname, ZZFH)
                except Exception as err:
                    pass
                finally:
                    if ZZFH:
                        ZZFH.close()
            
    except Exception as err:
        raise err
    finally:
        if inZFH:
            try:
                inZFH.close()
            except:
                pass

    ret = [top_el]
    if sub_els:
        ret = ret + sub_els

    return(ret)

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
            prefix = '/'.join([unpackdir, 'rootfs'])
            els = process_java_archive(prefix, f.encode('utf8'), None)
            if els:
                for el in els:
                    resultlist[el['location']] = json.dumps(el)

except Exception as err:
    print "WARN: analyzer unable to complete - exception: " + str(err)

if resultlist:
    ofile = os.path.join(outputdir, 'pkgs.java')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, resultlist)

sys.exit(0)
