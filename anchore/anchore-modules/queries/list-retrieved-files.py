#!/usr/bin/env python

import sys
import os
import re
import traceback

import anchore.anchore_utils

# main routine

try:
    config = anchore.anchore_utils.init_query_cmdline(sys.argv, "params: all | <file> <file> ...\nhelp: produce a list of all files that have been successfully retrieved and stored during analysis of this image.  Files listed here can be used as input to the get-retrieved-files query.")
except Exception as err:
    print str(err)
    sys.exit(1)

if not config:
    sys.exit(0)

if len(config['params']) <= 0:
    print "Query requires input: all | <fileA> <fileB> ..."

warns = list()
outlist = list()
outlist.append(["Image_Id", "Repo_Tags", "Stored_Namespace", "Stored_Filename", "Stored_File_Size_Bytes"])

tags = "none"
if config['meta']['humanname']:
    tags = config['meta']['humanname']
imgid = config['meta']['shortId']

try:
    # handle the good case, something is found resulting in data matching the required columns
    namespaces = anchore.anchore_utils.load_files_namespaces(config['imgid'])
    for namespace in namespaces:
        stored_files = anchore.anchore_utils.load_files_metadata(config['imgid'], namespace)
        for f in stored_files.keys():
            scrubbed_name = re.sub("imageroot", "", f)
            scrubbed_size = str(stored_files[f]['size'])
            outlist.append([imgid, tags, namespace, scrubbed_name, scrubbed_size])
except Exception as err:
    # handle the case where something wrong happened
    warns.append("Unable to load stored files data - try re-analyzing image")
    import traceback
    traceback.print_exc()
    print str(err)

anchore.anchore_utils.write_kvfile_fromlist(config['output'], outlist)
if len(warns) > 0:
    anchore.anchore_utils.write_plainfile_fromlist(config['output_warns'], warns)

sys.exit(0)



