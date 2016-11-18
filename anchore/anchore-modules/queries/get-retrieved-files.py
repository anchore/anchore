#!/usr/bin/env python

import sys
import os
import re
import traceback
import tarfile, io

import anchore.anchore_utils

def get_retrieved_file(imgid, srcfile, dstdir):
    ret = list()

    extractall = False
    if srcfile == 'all':
        extractall = True

    thedstdir = os.path.join(dstdir, imgid)

    tarfiles = list()
    namespaces = anchore.anchore_utils.load_files_namespaces(imgid)
    if namespaces:
        for namespace in namespaces:
            stored_data_tarfile = anchore.anchore_utils.load_files_tarfile(imgid, namespace)
            if stored_data_tarfile:
                tarfiles.append(stored_data_tarfile)
    else:
        stored_data_tarfile = anchore.anchore_utils.load_files_tarfile(imgid, 'retrieve_files')
        if stored_data_tarfile:
            tarfiles.append(stored_data_tarfile)

    for thetarfile in tarfiles:
        filetar = tarfile.open(thetarfile, mode='r:gz', format=tarfile.PAX_FORMAT)
        for ff in filetar.getmembers():
            patt = re.match("imageroot("+re.escape(srcfile)+")", ff.name)
            if extractall or patt:
                filetar.extract(ff, thedstdir)
                scrubbed_name = re.sub("imageroot", "", ff.name)
                ret.append([scrubbed_name, os.path.join(thedstdir, ff.name)])
        filetar.close()

    if namespaces:
        for namespace in namespaces:
            anchore.anchore_utils.del_files_cache(imgid)
    
    return(ret)

# main routine
try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: <source_filename> <destination_dir> ...\nhelp: Extract <source_filename> from stored files and copy to local host at <destination_dir>/<source_filename>.  Use 'all' as <source_filename> to extract all stored files into <destination_dir>")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) < 2:
    print "Query requires input: <source_filename> <destination_dir> ..."
    sys.exit(1)

srcfile = config['params'][0]
dstdir = config['params'][1]

warns = list()
outlist = list()
outlist.append(["Image_Id", "Repo_Tags", "Stored_File_Name", "Output_Location"])

tags = "none"
if config['meta']['humanname']:
    tags = config['meta']['humanname']
imgid = config['meta']['shortId']

try:
    # handle the good case, something is found resulting in data matching the required columns
    retlist = get_retrieved_file(config['imgid'], srcfile, dstdir)
    if retlist:
        for ret in retlist:
            srcname = ret[0]
            dstname = ret[1]
            outlist.append([imgid, tags, srcname, dstname])
    else:
        warns.append("Could not find any stored files matching input '"+str(srcfile)+"' in image's stored files")

except Exception as err:
    # handle the case where something wrong happened
    warns.append("Unable to load stored files data - try re-analyzing image")
    import traceback
    traceback.print_exc()
    print str(err)

# handle the no match case
if len(outlist) < 1:
    #outlist.append(["NOMATCH", "NOMATCH", "NOMATCH"])
    pass

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)
if len(warns) > 0:
    anchore.anchore_utils.write_plainfile_fromlist(config['output_warns'], warns)

sys.exit(0)

